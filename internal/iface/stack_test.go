//go:build linux

package iface

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/veth"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// newClientStack sets up a minimal IPv4+TCP client stack on ep with address
// 169.254.1.1/32 and a default route. Registers t.Cleanup(s.Close).
func newClientStack(t *testing.T, ep stack.LinkEndpoint) *stack.Stack {
	t.Helper()

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		HandleLocal:        true,
	})
	t.Cleanup(s.Close)

	const nicID = tcpip.NICID(1)
	if tcpipErr := s.CreateNIC(nicID, ep); tcpipErr != nil {
		t.Fatalf("CreateNIC: %v", tcpipErr)
	}
	if tcpipErr := s.EnableNIC(nicID); tcpipErr != nil {
		t.Fatalf("EnableNIC: %v", tcpipErr)
	}

	clientAddr := tcpip.AddrFrom4([4]byte{169, 254, 1, 1})
	protocolAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   clientAddr,
			PrefixLen: 32,
		},
	}
	if tcpipErr := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); tcpipErr != nil {
		t.Fatalf("AddProtocolAddress: %v", tcpipErr)
	}

	zeroSubnet, _ := tcpip.NewSubnet(
		tcpip.AddrFrom4([4]byte{}),
		tcpip.MaskFrom(strings.Repeat("\x00", 4)),
	)
	s.SetRouteTable([]tcpip.Route{{
		Destination: zeroSubnet,
		NIC:         nicID,
	}})

	return s
}

func TestServeIMDS_HTTPRoundTrip(t *testing.T) {
	ep1, ep2 := veth.NewPair(1500, veth.DefaultBacklogSize)
	t.Cleanup(ep1.Close) // closes both (shared veth)

	log := slog.Default()
	s, err := newIMDSStack(log, ethernet.New(ep1))
	require.NoError(t, err)
	t.Cleanup(s.Close)

	listener, err := gonet.ListenTCP(s, tcpip.FullAddress{Addr: imdsAddr, Port: 80}, ipv4.ProtocolNumber)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	go serveIMDS(ctx, listener, handler) //nolint:errcheck

	clientStack := newClientStack(t, ethernet.New(ep2))

	conn, err := gonet.DialContextTCP(ctx, clientStack,
		tcpip.FullAddress{Addr: imdsAddr, Port: 80}, ipv4.ProtocolNumber)
	require.NoError(t, err)
	defer conn.Close()

	fmt.Fprint(conn, "GET / HTTP/1.0\r\nHost: 169.254.169.254\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestServeIMDS_GracefulShutdown(t *testing.T) {
	ep1, _ := veth.NewPair(1500, veth.DefaultBacklogSize)
	t.Cleanup(ep1.Close)

	log := slog.Default()
	s, err := newIMDSStack(log, ethernet.New(ep1))
	require.NoError(t, err)
	t.Cleanup(s.Close)

	listener, err := gonet.ListenTCP(s, tcpip.FullAddress{Addr: imdsAddr, Port: 80}, ipv4.ProtocolNumber)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- serveIMDS(ctx, listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	}()

	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("serveIMDS did not shut down in time")
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
