// Package jwtsvid implements JWT-SVID issuance and JWKS serving for pve-imds.
//
// Tokens follow the SPIFFE JWT-SVID specification:
//   - Header: typ=JWT, alg=RS256, kid=<RFC 7638 thumbprint>
//   - Claims: sub (SPIFFE ID), aud, iat, exp, jti, plus PVE instance metadata
//
// The node's RSA private key is loaded once at construction time. The resulting
// [Signer] is safe for concurrent use.
package jwtsvid

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	"github.com/wyattanderson/pve-imds/internal/config"
)

// Signer holds the node's private key and issues RS256 JWT-SVIDs.
// It is safe for concurrent use after construction.
type Signer struct {
	cfg        config.JWTSVIDConfig
	joseSigner jose.Signer
	kid        string // pre-computed RFC 7638 thumbprint
}

// NewSigner reads the RSA private key at cfg.PrivateKeyPath, computes its kid,
// and prepares the jose.Signer. Returns an error if the key cannot be read or
// is not an RSA key.
func NewSigner(cfg config.JWTSVIDConfig) (*Signer, error) {
	privKey, err := loadRSAPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("jwtsvid: load private key from %s: %w", cfg.PrivateKeyPath, err)
	}
	return newSignerFromKey(cfg, privKey)
}

// newSignerFromKey constructs a Signer from an already-loaded key. Used by
// tests to avoid touching the filesystem.
func newSignerFromKey(cfg config.JWTSVIDConfig, privKey *rsa.PrivateKey) (*Signer, error) {
	kid, err := computeKID(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("jwtsvid: compute kid: %w", err)
	}

	signingKey := jose.SigningKey{Algorithm: jose.RS256, Key: privKey}
	opts := (&jose.SignerOptions{}).
		WithType("JWT").
		WithHeader("kid", kid)

	joseSig, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		return nil, fmt.Errorf("jwtsvid: create jose signer: %w", err)
	}

	return &Signer{cfg: cfg, joseSigner: joseSig, kid: kid}, nil
}

// IssueClaims carries the per-VM data included as extra JWT claims.
type IssueClaims struct {
	VMID     int
	UUID     string
	Name     string
	Hostname string
	Meta     map[string]string
}

// extraClaims is the JSON-serialisable form of the VM-specific extra claims.
type extraClaims struct {
	UUID     string            `json:"uuid"`
	Name     string            `json:"name,omitempty"`
	Hostname string            `json:"hostname,omitempty"`
	Meta     map[string]string `json:"meta,omitempty"`
}

// Issue mints a signed JWT-SVID for ic and the requested audience. The token
// is RS256-signed with the node's private key.
func (s *Signer) Issue(ic IssueClaims, audience string) (string, error) {
	now := time.Now()
	std := josejwt.Claims{
		Subject:  fmt.Sprintf("spiffe://%s/%d", s.cfg.TrustDomain, ic.VMID),
		Audience: josejwt.Audience{audience},
		IssuedAt: josejwt.NewNumericDate(now),
		Expiry:   josejwt.NewNumericDate(now.Add(s.cfg.TokenTTL)),
		ID:       uuid.New().String(),
	}
	extra := extraClaims{
		UUID:     ic.UUID,
		Name:     ic.Name,
		Hostname: ic.Hostname,
		Meta:     ic.Meta,
	}
	token, err := josejwt.Signed(s.joseSigner).Claims(std).Claims(extra).Serialize()
	if err != nil {
		return "", fmt.Errorf("jwtsvid: serialize token: %w", err)
	}
	return token, nil
}

// KID returns the key identifier embedded in every issued token's header.
func (s *Signer) KID() string { return s.kid }

// NodesDir returns the configured nodes directory used to build the JWKS.
func (s *Signer) NodesDir() string { return s.cfg.NodesDir }

// loadRSAPrivateKey reads path and returns the first RSA private key PEM block.
// Both PKCS#1 (RSA PRIVATE KEY) and PKCS#8 (PRIVATE KEY) are accepted.
func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		switch block.Type {
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			rk, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("PKCS8 key in %s is not RSA", path)
			}
			return rk, nil
		}
	}
	return nil, fmt.Errorf("no RSA private key block found in %s", path)
}

// computeKID returns the RFC 7638 JWK thumbprint (SHA-256, base64url without
// padding) for pub. The same function is used by both the signer and the JWKS
// builder so their kid values always agree.
func computeKID(pub *rsa.PublicKey) (string, error) {
	jwk := jose.JSONWebKey{Key: pub}
	thumb, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(thumb), nil
}
