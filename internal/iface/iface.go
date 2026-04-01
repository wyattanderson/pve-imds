//go:build linux

// Package iface manages AF_XDP sockets attached to tap interfaces.
package iface

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	xdplink "gvisor.dev/gvisor/pkg/tcpip/link/xdp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"

	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/imds"
	"github.com/wyattanderson/pve-imds/internal/imds/jwtsvid"
	"github.com/wyattanderson/pve-imds/internal/manager"
	"github.com/wyattanderson/pve-imds/internal/xdp"
)

// ctxHandlerKey is the context key used to store the matched mux pattern so
// that the promhttp metrics middleware can read it as a per-request label.
type ctxHandlerKey struct{}

var (
	ifaceInFlight = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pve_imds_http_in_flight_requests",
		Help: "Number of HTTP requests currently being served, by interface.",
	}, []string{"interface"})

	ifaceDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pve_imds_http_request_duration_seconds",
		Help:    "HTTP request latency by interface, handler, and status code.",
		Buckets: prometheus.DefBuckets,
	}, []string{"interface", "code", "handler"})

	ifaceRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pve_imds_http_requests_total",
		Help: "Total HTTP requests served, by interface, handler, and status code.",
	}, []string{"interface", "code", "handler"})
)

// Runtime is the per-interface worker. It sets up an AF_XDP socket, attaches
// an XDP program to redirect IMDS traffic, and serves HTTP on the gvisor stack.
type Runtime struct {
	log      *slog.Logger
	resolver *identity.Resolver
	server   imds.Server
	signer   *jwtsvid.Signer
	ifindex  int32  // primary identifier
	name     string // for logging/debugging only
}

// New constructs a Runtime for the given tap interface.
func New(log *slog.Logger, resolver *identity.Resolver, server imds.Server, signer *jwtsvid.Signer, ifindex int32, name string) *Runtime {
	return &Runtime{log: log, resolver: resolver, server: server, signer: signer, ifindex: ifindex, name: name}
}

// NewFactory returns a manager.RuntimeFactory that constructs a Runtime for
// each tap interface, sharing the provided logger, identity resolver, IMDS
// server, and JWT-SVID signer.
func NewFactory(log *slog.Logger, resolver *identity.Resolver, server imds.Server, signer *jwtsvid.Signer) manager.RuntimeFactory {
	return func(ifindex int32, name string) manager.InterfaceRuntime {
		return New(log, resolver, server, signer, ifindex, name)
	}
}

// Run implements manager.InterfaceRuntime. It blocks until ctx is cancelled or
// a fatal error occurs.
func (r *Runtime) Run(ctx context.Context) error {
	iface, err := net.InterfaceByIndex(int(r.ifindex))
	if err != nil {
		return fmt.Errorf("get interface %d (%s): %w", r.ifindex, r.name, err)
	}

	sockfd, err := syscall.Socket(unix.AF_XDP, syscall.SOCK_RAW, 0)
	if err != nil {
		return fmt.Errorf("create AF_XDP socket: %w", err)
	}
	defer syscall.Close(sockfd) //nolint:errcheck

	cleanup, err := xdp.LoadAndAttach(sockfd, iface)
	if err != nil {
		return err
	}
	defer cleanup()

	mac, err := tcpip.ParseMACAddress(iface.HardwareAddr.String())
	if err != nil {
		return fmt.Errorf("parse MAC address: %w", err)
	}

	le, err := xdplink.New(&xdplink.Options{
		FD:                sockfd,
		Address:           mac,
		Bind:              true,
		InterfaceIndex:    iface.Index,
		RXChecksumOffload: true,
	})
	if err != nil {
		return fmt.Errorf("create XDP link endpoint: %w", err)
	}

	s, err := newIMDSStack(r.log, le)
	if err != nil {
		return err
	}
	defer s.Close()

	listener, err := gonet.ListenTCP(s, tcpip.FullAddress{Addr: imdsAddr, Port: 80}, ipv4.ProtocolNumber)
	if err != nil {
		return fmt.Errorf("listen TCP 169.254.169.254:80: %w", err)
	}
	defer listener.Close() //nolint:errcheck

	log := r.log.With("iface", r.name)
	labels := prometheus.Labels{"interface": r.name}
	base := r.server.NewHandler(r.resolver, r.name, r.ifindex)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /pve-imds/jwtsvid", jwtsvid.NewIssueHandler(r.signer, r.resolver, r.name, r.ifindex))
	mux.HandleFunc("GET /.well-known/jwks.json", jwtsvid.NewJWKSHandler(r.signer.NodesDir(), log))
	mux.Handle("/", base)

	// handlerLabel is a promhttp option that reads the matched mux pattern from
	// the request context, where routeLabeled stores it before each request.
	handlerLabel := promhttp.WithLabelFromCtx("handler", func(ctx context.Context) string {
		v, _ := ctx.Value(ctxHandlerKey{}).(string)
		return v
	})

	// routeLabeled wraps h by peeking at the mux routing to store the matched
	// pattern in the request context before calling h. This must sit outside
	// the promhttp instrumentation wrappers so that InstrumentHandlerDuration
	// and InstrumentHandlerCounter receive a request whose context already
	// contains the handler label — they read context after the inner handler
	// returns, not from any modified copy created inside.
	routeLabeled := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, pattern := mux.Handler(r)
			ctx := context.WithValue(r.Context(), ctxHandlerKey{}, pattern)
			h.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	instrumented := promhttp.InstrumentHandlerInFlight(
		ifaceInFlight.With(labels),
		routeLabeled(
			promhttp.InstrumentHandlerDuration(
				ifaceDuration.MustCurryWith(labels),
				promhttp.InstrumentHandlerCounter(
					ifaceRequests.MustCurryWith(labels),
					mux,
					handlerLabel,
				),
				handlerLabel,
			),
		),
	)
	handler := imds.LoggingMiddleware(log, instrumented)
	return imds.Serve(ctx, listener, handler)
}
