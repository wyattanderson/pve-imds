package jwtsvid

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/pve-imds/internal/config"
	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/vmconfig"
)

// fakeResolver returns a fixed VMRecord, or an error when rec is nil.
type fakeResolver struct {
	rec *identity.VMRecord
	err error
}

func (f *fakeResolver) RecordByName(_ string, _ int32) (*identity.VMRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.rec, nil
}

func testRecord() *identity.VMRecord {
	return &identity.VMRecord{
		Node:     "pve-node1",
		VMID:     100,
		NetIndex: 0,
		IfIndex:  3,
		Config: &vmconfig.VMConfig{
			Name: "test-vm",
			SMBIOS: map[string]string{
				"uuid": "86f5aa5e-08a3-40cb-a642-efad20b5b061",
			},
			Tags: []string{"prod"},
			Raw:  map[string]string{},
		},
	}
}

func testHandlerSigner(t *testing.T) (*Signer, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cfg := config.JWTSVIDConfig{TrustDomain: "pve.example.com", TokenTTL: 5 * time.Minute}
	s, err := newSignerFromKey(cfg, key)
	require.NoError(t, err)
	return s, key
}

func postForm(t *testing.T, handler http.Handler, form url.Values) *http.Response {
	t.Helper()
	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"/pve-imds/jwtsvid",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w.Result()
}

func TestIssueHandlerRejectsGET(t *testing.T) {
	s, _ := testHandlerSigner(t)
	handler := NewIssueHandler(s, &fakeResolver{rec: testRecord()}, "tap100i0", 3)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/pve-imds/jwtsvid", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestIssueHandlerMissingAudience(t *testing.T) {
	s, _ := testHandlerSigner(t)
	handler := NewIssueHandler(s, &fakeResolver{rec: testRecord()}, "tap100i0", 3)

	resp := postForm(t, handler, url.Values{})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestIssueHandlerEmptyAudience(t *testing.T) {
	s, _ := testHandlerSigner(t)
	handler := NewIssueHandler(s, &fakeResolver{rec: testRecord()}, "tap100i0", 3)

	resp := postForm(t, handler, url.Values{"audience": {""}})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestIssueHandlerSuccess(t *testing.T) {
	s, key := testHandlerSigner(t)
	handler := NewIssueHandler(s, &fakeResolver{rec: testRecord()}, "tap100i0", 3)

	resp := postForm(t, handler, url.Values{"audience": {"https://example.com"}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))

	// Read and parse the raw token.
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	token := strings.TrimSpace(string(body[:n]))

	tok, err := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	var claims map[string]any
	require.NoError(t, tok.Claims(&key.PublicKey, &claims))

	assert.Equal(t, "spiffe://pve.example.com/100", claims["sub"])
	assert.Equal(t, "86f5aa5e-08a3-40cb-a642-efad20b5b061", claims["uuid"])
	assert.Equal(t, "test-vm", claims["name"])
}

func TestIssueHandlerResolverError(t *testing.T) {
	s, _ := testHandlerSigner(t)
	handler := NewIssueHandler(s, &fakeResolver{err: errors.New("not found")}, "tap100i0", 3)

	resp := postForm(t, handler, url.Values{"audience": {"https://example.com"}})
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}
