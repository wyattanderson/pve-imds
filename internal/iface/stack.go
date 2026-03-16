//go:build linux

package iface

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/wyattanderson/pve-imds/internal/xdp"
)

var imdsAddr = tcpip.AddrFrom4([4]byte{169, 254, 169, 254})

// newIMDSStack creates a gvisor TCP/IP stack with 169.254.169.254/32 bound to
// nicID 1, wrapping le with NewStaticARPEndpoint to learn VM MAC/IP pairs.
// On success the caller must defer s.Close().
func newIMDSStack(log *slog.Logger, le stack.LinkEndpoint) (*stack.Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		HandleLocal:        true,
	})

	const nicID = tcpip.NICID(1)

	if tcpipErr := s.CreateNIC(nicID, xdp.NewStaticARPEndpoint(log, le, s, nicID)); tcpipErr != nil {
		s.Close()
		return nil, fmt.Errorf("create NIC: %v", tcpipErr)
	}
	if tcpipErr := s.EnableNIC(nicID); tcpipErr != nil {
		s.Close()
		return nil, fmt.Errorf("enable NIC: %v", tcpipErr)
	}

	protocolAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   imdsAddr,
			PrefixLen: 32,
		},
	}
	if tcpipErr := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); tcpipErr != nil {
		s.Close()
		return nil, fmt.Errorf("add protocol address: %v", tcpipErr)
	}

	zeroSubnet, err := tcpip.NewSubnet(
		tcpip.AddrFrom4([4]byte{}),
		tcpip.MaskFrom(strings.Repeat("\x00", 4)),
	)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("create default subnet: %w", err)
	}
	s.SetRouteTable([]tcpip.Route{{
		Destination: zeroSubnet,
		NIC:         nicID,
	}})

	return s, nil
}

// serveIMDS runs handler over listener until ctx is cancelled, then shuts
// down gracefully with a 5-second timeout. It does not close listener.
func serveIMDS(ctx context.Context, listener net.Listener, handler http.Handler) error {
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
