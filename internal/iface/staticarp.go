//go:build linux

package iface

import (
	"log/slog"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Endpoint wraps a lower LinkEndpoint and learns static ARP entries from
// incoming packets, so the gvisor stack can reply to the originating VM.
//
// It also tracks the destination MAC of incoming IPv4 packets and uses it as
// the source MAC on outbound frames. This ensures correct behaviour in both
// the direct-ARP path (VM discovered us and sends dst=ourMAC) and the default-
// gateway path (VM routes to 169.254.169.254 via a gateway and sends
// dst=gatewayMAC — replies must come from gatewayMAC or the VM will drop them).
type Endpoint struct {
	nested.Endpoint
	log             *slog.Logger
	s               *stack.Stack
	nicID           tcpip.NICID
	preferredSrcMAC atomic.Value // stores tcpip.LinkAddress once first unicast inbound dst is seen
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
// and tracks the destination MAC so we can mirror it as our outbound source.
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

		// Track the ethernet destination of every inbound unicast frame. Replies
		// must carry this MAC as the source so that the VM accepts them regardless
		// of whether it reached us directly (via ARP) or through a gateway.
		if dstMAC := eth.DestinationAddress(); len(dstMAC) > 0 && dstMAC[0]&0x01 == 0 {
			e.preferredSrcMAC.Store(dstMAC)
		}
	}
	e.Endpoint.DeliverNetworkPacket(protocol, pkt)
}

// AddHeader rewrites the outbound source MAC to match the destination MAC seen
// on inbound frames before delegating to the child endpoint to encode the
// ethernet header.
func (e *Endpoint) AddHeader(pkt *stack.PacketBuffer) {
	if mac, ok := e.preferredSrcMAC.Load().(tcpip.LinkAddress); ok && len(mac) > 0 {
		pkt.EgressRoute.LocalLinkAddress = mac
	}
	e.Endpoint.AddHeader(pkt)
}
