package jwtsvid

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/pve-imds/internal/config"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func testSigner(t *testing.T) *Signer {
	t.Helper()
	cfg := config.JWTSVIDConfig{
		TrustDomain: "pve.example.com",
		TokenTTL:    5 * time.Minute,
		NodesDir:    "/etc/pve/nodes",
	}
	s, err := newSignerFromKey(cfg, testKey(t))
	require.NoError(t, err)
	return s
}

func testClaims(vmid int) IssueClaims {
	return IssueClaims{
		VMID:     vmid,
		UUID:     "86f5aa5e-08a3-40cb-a642-efad20b5b061",
		Name:     "test-vm",
		Hostname: "test-vm",
		Meta:     map[string]string{"pve:vmid": "100", "pve:node": "pve1"},
	}
}

// parseTokenPublic verifies the token signature with key and returns the claims.
func parseTokenPublic(t *testing.T, key *rsa.PrivateKey, token string) map[string]any {
	t.Helper()
	tok, err := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, tok.Claims(&key.PublicKey, &claims))
	return claims
}

func TestIssueRS256Header(t *testing.T) {
	key := testKey(t)
	cfg := config.JWTSVIDConfig{TrustDomain: "pve.example.com", TokenTTL: 5 * time.Minute}
	s, err := newSignerFromKey(cfg, key)
	require.NoError(t, err)

	token, err := s.Issue(testClaims(100), "https://example.com")
	require.NoError(t, err)

	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	require.Len(t, jws.Signatures, 1)

	h := jws.Signatures[0].Header
	assert.Equal(t, "JWT", h.ExtraHeaders["typ"])
	assert.Equal(t, string(jose.RS256), h.Algorithm)
	assert.Equal(t, s.KID(), h.KeyID)
}

func TestIssueSubClaim(t *testing.T) {
	key := testKey(t)
	cfg := config.JWTSVIDConfig{TrustDomain: "pve.example.com", TokenTTL: 5 * time.Minute}
	s, err := newSignerFromKey(cfg, key)
	require.NoError(t, err)

	token, err := s.Issue(testClaims(42), "aud")
	require.NoError(t, err)

	claims := parseTokenPublic(t, key, token)
	assert.Equal(t, "spiffe://pve.example.com/42", claims["sub"])
}

func TestIssueAudClaim(t *testing.T) {
	key := testKey(t)
	cfg := config.JWTSVIDConfig{TrustDomain: "pve.example.com", TokenTTL: 5 * time.Minute}
	s, err := newSignerFromKey(cfg, key)
	require.NoError(t, err)

	token, err := s.Issue(testClaims(100), "https://relying-party.example.com")
	require.NoError(t, err)

	claims := parseTokenPublic(t, key, token)
	// JWT aud can be a string or []interface{} depending on how it was encoded.
	switch v := claims["aud"].(type) {
	case string:
		assert.Equal(t, "https://relying-party.example.com", v)
	case []any:
		require.Len(t, v, 1)
		assert.Equal(t, "https://relying-party.example.com", v[0])
	default:
		t.Fatalf("unexpected aud type %T", v)
	}
}

func TestIssueExpiry(t *testing.T) {
	key := testKey(t)
	ttl := 10 * time.Minute
	cfg := config.JWTSVIDConfig{TrustDomain: "pve.example.com", TokenTTL: ttl}
	s, err := newSignerFromKey(cfg, key)
	require.NoError(t, err)

	before := time.Now()
	token, err := s.Issue(testClaims(100), "aud")
	require.NoError(t, err)

	claims := parseTokenPublic(t, key, token)
	iat := time.Unix(int64(claims["iat"].(float64)), 0)
	exp := time.Unix(int64(claims["exp"].(float64)), 0)

	assert.WithinDuration(t, before, iat, 2*time.Second)
	assert.WithinDuration(t, iat.Add(ttl), exp, 2*time.Second)
}

func TestIssueJTIUnique(t *testing.T) {
	key := testKey(t)
	cfg := config.JWTSVIDConfig{TrustDomain: "pve.example.com", TokenTTL: 5 * time.Minute}
	s, err := newSignerFromKey(cfg, key)
	require.NoError(t, err)

	token1, err := s.Issue(testClaims(100), "aud")
	require.NoError(t, err)
	token2, err := s.Issue(testClaims(100), "aud")
	require.NoError(t, err)

	claims1 := parseTokenPublic(t, key, token1)
	claims2 := parseTokenPublic(t, key, token2)
	assert.NotEqual(t, claims1["jti"], claims2["jti"])
}

func TestIssueExtraClaims(t *testing.T) {
	key := testKey(t)
	cfg := config.JWTSVIDConfig{TrustDomain: "pve.example.com", TokenTTL: 5 * time.Minute}
	s, err := newSignerFromKey(cfg, key)
	require.NoError(t, err)

	ic := IssueClaims{
		VMID:     100,
		UUID:     "test-uuid",
		Name:     "my-vm",
		Hostname: "my-vm",
		Meta:     map[string]string{"pve:vmid": "100", "pve:node": "node1"},
	}
	token, err := s.Issue(ic, "aud")
	require.NoError(t, err)

	claims := parseTokenPublic(t, key, token)
	assert.Equal(t, "test-uuid", claims["uuid"])
	assert.Equal(t, "my-vm", claims["name"])
	assert.Equal(t, "my-vm", claims["hostname"])

	meta, ok := claims["meta"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "100", meta["pve:vmid"])
	assert.Equal(t, "node1", meta["pve:node"])
}

func TestKIDConsistency(t *testing.T) {
	key := testKey(t)

	// kid derived from the private key's public part
	kidFromPriv, err := computeKID(&key.PublicKey)
	require.NoError(t, err)

	// kid derived from a separately constructed *rsa.PublicKey with same N/E
	pub := &rsa.PublicKey{N: key.N, E: key.E}
	kidFromPub, err := computeKID(pub)
	require.NoError(t, err)

	assert.Equal(t, kidFromPriv, kidFromPub)
}

func TestKIDIsBase64URL(t *testing.T) {
	key := testKey(t)
	kid, err := computeKID(&key.PublicKey)
	require.NoError(t, err)

	// Must be base64url without padding.
	assert.NotContains(t, kid, "=")
	assert.NotContains(t, kid, "+")
	assert.NotContains(t, kid, "/")

	_, err = base64.RawURLEncoding.DecodeString(kid)
	assert.NoError(t, err, "kid must be valid base64url")
}

func TestTokenIsCompact(t *testing.T) {
	s := testSigner(t)
	token, err := s.Issue(testClaims(100), "aud")
	require.NoError(t, err)

	// Compact JWS has exactly two dots (header.payload.signature).
	assert.Equal(t, 2, strings.Count(token, "."), "token must be compact-serialized JWT")
}
