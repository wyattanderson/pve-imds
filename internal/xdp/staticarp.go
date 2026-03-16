//go:build linux

package xdp

import (
	"log/slog"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Endpoint wraps a lower LinkEndpoint and learns static ARP entries from
// incoming packets, so the gvisor stack can reply to the originating VM.
type Endpoint struct {
	nested.Endpoint
	log   *slog.Logger
	s     *stack.Stack
	nicID tcpip.NICID
}

var _ stack.GSOEndpoint = (*Endpoint)(nil)
var _ stack.LinkEndpoint = (*Endpoint)(nil)
var _ stack.NetworkDispatcher = (*Endpoint)(nil)

// NewStaticARPEndpoint constructs an Endpoint wrapping lower.
func NewStaticARPEndpoint(log *slog.Logger, lower stack.LinkEndpoint, s *stack.Stack, nicID tcpip.NICID) *Endpoint {
	e := &Endpoint{
		log:   log,
		s:     s,
		nicID: nicID,
	}
	e.Endpoint.Init(lower, e)
	return e
}

// DeliverNetworkPacket learns the source MAC/IP from each incoming IPv4 packet
// before passing it up to the network stack.
func (e *Endpoint) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if protocol == header.IPv4ProtocolNumber {
		clone := pkt.CloneToInbound()
		defer clone.DecRef()

		clone.LinkHeader().Consume(header.EthernetMinimumSize)
		clone.NetworkHeader().Consume(header.IPv4MinimumSize)

		eth := header.Ethernet(clone.LinkHeader().Slice())
		ipv4h := header.IPv4(clone.NetworkHeader().Slice())

		if err := e.s.AddStaticNeighbor(e.nicID, protocol, ipv4h.SourceAddress(), eth.SourceAddress()); err != nil {
			e.log.Warn("failed to add static neighbor", "err", err)
		}
	}
	e.Endpoint.DeliverNetworkPacket(protocol, pkt)
}
