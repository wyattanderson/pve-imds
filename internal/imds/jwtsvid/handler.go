package jwtsvid

import (
	"fmt"
	"net/http"

	"github.com/wyattanderson/pve-imds/internal/imds"
	"github.com/wyattanderson/pve-imds/internal/imds/openstack"
)

// NewIssueHandler returns an http.HandlerFunc that serves POST /pve-imds/jwtsvid.
//
// The request must be an application/x-www-form-urlencoded POST with a
// non-empty "audience" field. On success the response body is the raw
// compact-serialized JWT token with Content-Type text/plain.
func NewIssueHandler(signer *Signer, resolver imds.Resolver, name string, ifindex int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		audience := r.FormValue("audience")
		if audience == "" {
			http.Error(w, `"audience" form field is required`, http.StatusBadRequest)
			return
		}

		rec, err := resolver.RecordByName(name, ifindex)
		if err != nil {
			http.Error(w, fmt.Sprintf("identity lookup failed: %v", err), http.StatusServiceUnavailable)
			return
		}

		md := openstack.MetadataFromRecord(rec)
		ic := IssueClaims{
			VMID:     rec.VMID,
			UUID:     md.UUID,
			Name:     md.Name,
			Hostname: md.Hostname,
			Meta:     md.Meta,
		}

		token, err := signer.Issue(ic, audience)
		if err != nil {
			http.Error(w, "token issuance failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, token) //nolint:errcheck
	}
}
