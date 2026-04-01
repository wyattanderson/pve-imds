package jwtsvid

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/pve-imds/internal/config"
)

var nopLog = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

// makeCertPEM generates a self-signed RSA certificate and writes it as PEM to
// path. Returns the private key for kid comparison.
func makeCertPEM(t *testing.T, path string) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pve-ssl"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close() //nolint:errcheck
	require.NoError(t, pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return key
}

// makeNodeDir creates nodesDir/<name>/pve-ssl.pem and returns the private key.
func makeNodeDir(t *testing.T, nodesDir, name string) *rsa.PrivateKey {
	t.Helper()
	dir := filepath.Join(nodesDir, name)
	require.NoError(t, os.Mkdir(dir, 0o755))
	return makeCertPEM(t, filepath.Join(dir, "pve-ssl.pem"))
}

func decodeJWKS(t *testing.T, resp *http.Response) []jose.JSONWebKey {
	t.Helper()
	var body struct {
		Keys []jose.JSONWebKey `json:"keys"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return body.Keys
}

func getJWKS(t *testing.T, nodesDir string) *http.Response {
	t.Helper()
	handler := NewJWKSHandler(nodesDir, nopLog)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w.Result()
}

func TestJWKSEmptyDir(t *testing.T) {
	dir := t.TempDir()
	resp := getJWKS(t, dir)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	keys := decodeJWKS(t, resp)
	assert.Empty(t, keys)
}

func TestJWKSSingleNode(t *testing.T) {
	dir := t.TempDir()
	key := makeNodeDir(t, dir, "pve-node1")

	resp := getJWKS(t, dir)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	keys := decodeJWKS(t, resp)
	require.Len(t, keys, 1)

	jwk := keys[0]
	assert.Equal(t, string(jose.RS256), jwk.Algorithm)
	assert.Equal(t, "sig", jwk.Use)

	// kid must match computeKID for the same public key.
	expected, err := computeKID(&key.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, expected, jwk.KeyID)
}

func TestJWKSMultiNode(t *testing.T) {
	dir := t.TempDir()
	makeNodeDir(t, dir, "pve-node1")
	makeNodeDir(t, dir, "pve-node2")

	resp := getJWKS(t, dir)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	keys := decodeJWKS(t, resp)
	assert.Len(t, keys, 2)
}

func TestJWKSSkipsBadCert(t *testing.T) {
	dir := t.TempDir()

	// Bad node: directory exists but cert is garbage.
	badDir := filepath.Join(dir, "bad-node")
	require.NoError(t, os.Mkdir(badDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(badDir, "pve-ssl.pem"), []byte("not a cert"), 0o644))

	// Good node.
	makeNodeDir(t, dir, "good-node")

	resp := getJWKS(t, dir)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	keys := decodeJWKS(t, resp)
	assert.Len(t, keys, 1, "bad node should be skipped; good node should still appear")
}

func TestJWKSKIDMatchesSigner(t *testing.T) {
	dir := t.TempDir()
	certKey := makeNodeDir(t, dir, "pve-node1")

	// Build the signer from the same key.
	cfg := config.JWTSVIDConfig{TrustDomain: "pve.example.com", TokenTTL: 5 * time.Minute}
	s, err := newSignerFromKey(cfg, certKey)
	require.NoError(t, err)

	resp := getJWKS(t, dir)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	keys := decodeJWKS(t, resp)
	require.Len(t, keys, 1)

	assert.Equal(t, s.KID(), keys[0].KeyID,
		"JWKS kid must match the Signer kid for the same key pair")
}

func TestJWKSHandlerMethodNotAllowed(t *testing.T) {
	dir := t.TempDir()
	handler := NewJWKSHandler(dir, nopLog)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestJWKSNonDirEntriesIgnored(t *testing.T) {
	dir := t.TempDir()
	// Place a regular file in the nodes dir — should be ignored.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "not-a-dir"), []byte("x"), 0o644))
	makeNodeDir(t, dir, "pve-node1")

	resp := getJWKS(t, dir)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	keys := decodeJWKS(t, resp)
	assert.Len(t, keys, 1)
}
