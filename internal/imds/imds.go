package imds

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/wyattanderson/pve-imds/internal/identity"
)

// Resolver resolves VM identity for an incoming IMDS request. The method
// signature matches identity.Resolver.RecordByName so the production
// *identity.Resolver satisfies this interface without any wrapper.
type Resolver interface {
	RecordByName(ifname string, ifindex int32) (*identity.VMRecord, error)
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
func NewHandler(resolver Resolver, name string, ifindex int32) http.Handler {
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
			userData, ok := ParseUserData(rec.Config.Description)
			if !ok {
				http.NotFound(w, req)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			fmt.Fprint(w, userData)
		default:
			http.NotFound(w, req)
		}
	})
}

// Serve runs handler over listener until ctx is cancelled, then shuts down
// gracefully with a 5-second timeout. It does not close listener.
func Serve(ctx context.Context, listener net.Listener, handler http.Handler) error {
	server := &http.Server{Handler: handler}

	g, _ := errgroup.WithContext(ctx)
	g.Go(func() error {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	g.Go(func() error {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutCtx)
	})
	return g.Wait()
}
