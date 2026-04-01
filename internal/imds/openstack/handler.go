// Package openstack implements an OpenStack Nova metadata-compatible IMDS server.
//
// URL structure served:
//
//	GET /openstack                              → newline-separated version list
//	GET /openstack/{version}                   → newline-separated file list
//	GET /openstack/{version}/meta_data.json    → JSON instance metadata
//	GET /openstack/{version}/network_data.json → JSON network configuration
//	GET /openstack/{version}/user_data         → raw user-data (404 if absent)
//	GET /openstack/{version}/vendor_data.json  → empty JSON object
//	GET /openstack/{version}/vendor_data2.json → empty JSON object
//
// Any version string is accepted in the path; all return identical data.
// cloud-init's OpenStack datasource reads /openstack to discover available
// versions, then selects the newest one it recognises. We advertise only
// "latest" so cloud-init always uses /openstack/latest/…
//
// Detection: set "smbios1: product=OpenStack Nova" in the Proxmox VM config
// (or VM template). cloud-init's ds_detect() checks this DMI product name.
package openstack

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/imds"
)

const versionListing = "latest\n"

// fileListing is the directory listing returned for GET /openstack/{version}.
// cloud-init does not require this listing, but it is useful for debugging.
const fileListing = "meta_data.json\nnetwork_data.json\nuser_data\nvendor_data.json\nvendor_data2.json\n"

type server struct{}

// NewServer returns an [imds.Server] that serves OpenStack Nova-compatible
// IMDS responses.
func NewServer() imds.Server {
	return &server{}
}

// NewHandler implements [imds.Server]. It returns an http.Handler that routes
// /openstack/… requests for the tap interface identified by name and ifindex.
func (s *server) NewHandler(resolver imds.Resolver, name string, ifindex int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rec, err := resolver.RecordByName(name, ifindex)
		if err != nil {
			http.Error(w, fmt.Sprintf("identity lookup failed: %v", err), http.StatusServiceUnavailable)
			return
		}

		// Normalise the path: strip leading/trailing slashes, then split into
		// at most 3 segments: ["openstack", version, file].
		//
		// Examples:
		//   "/openstack"                        → ["openstack"]
		//   "/openstack/latest"                 → ["openstack", "latest"]
		//   "/openstack/latest/meta_data.json"  → ["openstack", "latest", "meta_data.json"]
		path := strings.Trim(req.URL.Path, "/")
		parts := strings.SplitN(path, "/", 3)

		if parts[0] != "openstack" {
			// cloud-init's OpenStack datasource also crawls the EC2 metadata
			// endpoint as a secondary source via _read_ec2_metadata(). Return
			// an empty 200 for the EC2 metadata root so it sees no EC2
			// metadata without producing errors. Empty body → empty listing →
			// no sub-path requests; cloud-init treats ec2_metadata as {}.
			if req.URL.Path == "/latest/meta-data" || req.URL.Path == "/latest/meta-data/" {
				w.WriteHeader(http.StatusOK)
				return
			}
			http.NotFound(w, req)
			return
		}

		switch len(parts) {
		case 1:
			// GET /openstack — version listing consumed by cloud-init detection.
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, versionListing) //nolint:errcheck

		case 2:
			// GET /openstack/{version} — file listing (informational).
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, fileListing) //nolint:errcheck

		case 3:
			// GET /openstack/{version}/{file}
			serveFile(w, req, rec, parts[2])
		}
	})
}

// serveFile dispatches a /openstack/{version}/{file} request.
func serveFile(w http.ResponseWriter, req *http.Request, rec *identity.VMRecord, file string) {
	switch file {
	case "meta_data.json":
		serveJSON(w, MetadataFromRecord(rec))

	case "network_data.json":
		serveJSON(w, networkDataFromRecord(rec))

	case "user_data":
		userData, ok := imds.ParseUserData(rec.Config.Description)
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		fmt.Fprint(w, userData) //nolint:errcheck

	case "vendor_data.json", "vendor_data2.json":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "{}\n") //nolint:errcheck

	default:
		http.NotFound(w, req)
	}
}

// serveJSON marshals v to JSON and writes it to w with an application/json
// Content-Type. If marshaling fails, it writes a 500 response instead.
func serveJSON(w http.ResponseWriter, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)       //nolint:errcheck
	fmt.Fprint(w, "\n") //nolint:errcheck
}
