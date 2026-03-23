// Package ec2 implements an EC2-compatible IMDS server.
package ec2

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/wyattanderson/pve-imds/internal/imds"
)

type server struct{}

// NewServer returns an [imds.Server] that serves EC2-compatible IMDS responses.
func NewServer() imds.Server {
	return &server{}
}

// NewHandler returns an http.Handler that serves EC2-compatible IMDS responses
// for the tap interface identified by name and ifindex.
//
// Each request is handled as follows:
//  1. Resolve VM identity via resolver.RecordByName.
//  2. Build an InstanceMetadata from the resolved VMRecord.
//  3. Dispatch on the URL path category (meta-data, user-data).
//
// The URL path format is /{version}/{category}/..., e.g.:
//
//	GET /2009-04-04/meta-data/instance-id
//	GET /latest/meta-data/
//	GET /latest/user-data
//
// Any version string is accepted; all versions return the same data.
func (s *server) NewHandler(resolver imds.Resolver, name string, ifindex int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rec, err := resolver.RecordByName(name, ifindex)
		if err != nil {
			http.Error(w, fmt.Sprintf("identity lookup failed: %v", err), http.StatusServiceUnavailable)
			return
		}

		// Path format: /{version}/{category}/...
		//   parts[0] = ""           (before the leading slash)
		//   parts[1] = version      ("2009-04-04", "latest", …)
		//   parts[2] = category     ("meta-data", "user-data")
		//   parts[3] = rest         (optional sub-path within category)
		parts := strings.SplitN(req.URL.Path, "/", 4)
		if len(parts) < 3 {
			http.NotFound(w, req)
			return
		}
		category := parts[2]
		var rest string
		if len(parts) == 4 {
			rest = parts[3]
		}

		switch category {
		case "meta-data":
			md := MetadataFromRecord(rec)
			serveTree(w, rest, buildTree(md))
		case "user-data":
			userData, ok := imds.ParseUserData(rec.Config.Description)
			if !ok {
				http.NotFound(w, req)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			fmt.Fprint(w, userData) //nolint:errcheck
		default:
			http.NotFound(w, req)
		}
	})
}
