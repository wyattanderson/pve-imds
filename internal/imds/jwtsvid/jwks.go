package jwtsvid

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-jose/go-jose/v4"
)

// jwksResponse is the wire format for a JSON Web Key Set document.
type jwksResponse struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

// NewJWKSHandler returns an http.HandlerFunc that serves GET /.well-known/jwks.json.
// It reads all pve-ssl.pem files from nodesDir/<node>/pve-ssl.pem on each
// request. Nodes whose certificate is absent or malformed are skipped with a
// warning log; a partial JWKS is still useful to relying parties.
func NewJWKSHandler(nodesDir string, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		keys, err := buildJWKS(nodesDir, log)
		if err != nil {
			http.Error(w, "failed to build JWKS", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(keys); err != nil {
			log.Warn("jwtsvid: failed to write JWKS response", "err", err)
		}
	}
}

// buildJWKS scans nodesDir for pve-ssl.pem files and returns a JWKS containing
// the RSA public key from each, with kid set to the RFC 7638 thumbprint.
func buildJWKS(nodesDir string, log *slog.Logger) (jwksResponse, error) {
	entries, err := os.ReadDir(nodesDir)
	if err != nil {
		return jwksResponse{}, fmt.Errorf("jwtsvid: read nodes dir %s: %w", nodesDir, err)
	}

	keys := make([]jose.JSONWebKey, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		certPath := filepath.Join(nodesDir, e.Name(), "pve-ssl.pem")
		pub, err := loadRSAPublicKeyFromCert(certPath)
		if err != nil {
			log.Warn("jwtsvid: skipping node cert", "path", certPath, "err", err)
			continue
		}
		kid, err := computeKID(pub)
		if err != nil {
			log.Warn("jwtsvid: skipping node cert (kid computation failed)", "path", certPath, "err", err)
			continue
		}
		keys = append(keys, jose.JSONWebKey{
			Key:       pub,
			KeyID:     kid,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		})
	}

	return jwksResponse{Keys: keys}, nil
}

// loadRSAPublicKeyFromCert reads the first CERTIFICATE PEM block from path and
// returns its RSA public key. Returns an error if the file cannot be read, no
// certificate block is found, or the key is not RSA.
func loadRSAPublicKeyFromCert(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate %s: %w", path, err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate in %s does not contain an RSA public key", path)
	}
	return pub, nil
}
