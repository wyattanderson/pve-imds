// Package imds provides the core IMDS server infrastructure: the Server
// interface, the Resolver interface, and the Serve function. Protocol-specific
// implementations live in sub-packages (e.g. imds/ec2).
package imds

import (
	"context"
	"errors"
	"net"
	"net/http"
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

// Server creates per-interface HTTP handlers for IMDS requests. Each call to
// NewHandler produces an independent handler bound to the named tap interface.
type Server interface {
	NewHandler(resolver Resolver, name string, ifindex int32) http.Handler
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
