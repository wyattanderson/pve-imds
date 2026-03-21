package imds

import (
	"context"
	"errors"
	"fmt"
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

// NewHandler returns an http.Handler that resolves the VM identity for the
// given tap interface and writes a plain-text summary.
func NewHandler(resolver Resolver, name string, ifindex int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rec, err := resolver.RecordByName(name, ifindex)
		if err != nil {
			http.Error(w, fmt.Sprintf("identity lookup failed: %v", err), http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "node:     %s\n", rec.Node)
		fmt.Fprintf(w, "vmid:     %d\n", rec.VMID)
		fmt.Fprintf(w, "netindex: %d\n", rec.NetIndex)
		fmt.Fprintf(w, "pid:      %d\n", rec.ProcessInfo.PID)
		fmt.Fprintf(w, "\n[vmconfig]\n")
		fmt.Fprintf(w, "name:        %s\n", rec.Config.Name)
		fmt.Fprintf(w, "ostype:      %s\n", rec.Config.OSType)
		fmt.Fprintf(w, "description: %s\n", rec.Config.Description)
		fmt.Fprintf(w, "tags:        %v\n", rec.Config.Tags)
		for idx, dev := range rec.Config.Networks {
			fmt.Fprintf(w, "net%d:        model=%s mac=%s bridge=%s\n", idx, dev.Model, dev.MAC, dev.Bridge)
		}
		for k, v := range rec.Config.Raw {
			fmt.Fprintf(w, "%s: %s\n", k, v)
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
