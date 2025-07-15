package staticarp

import (
	"log"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Endpoint struct {
	nested.Endpoint
	s     *stack.Stack
	nicID tcpip.NICID
}

var _ stack.GSOEndpoint = (*Endpoint)(nil)
var _ stack.LinkEndpoint = (*Endpoint)(nil)
var _ stack.NetworkDispatcher = (*Endpoint)(nil)

func NewEndpoint(lower stack.LinkEndpoint, s *stack.Stack, nicID tcpip.NICID) *Endpoint {
	e := &Endpoint{
		s:     s,
		nicID: nicID,
	}
	e.Endpoint.Init(lower, e)
	return e
}

func (e *Endpoint) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	clone := pkt.CloneToInbound()
	defer clone.DecRef()

	clone.LinkHeader().Consume(header.EthernetMinimumSize)
	clone.NetworkHeader().Consume(header.IPv4MinimumSize)

	eth := header.Ethernet(clone.LinkHeader().Slice())
	ipv4 := header.IPv4(clone.NetworkHeader().Slice())

	// TODO:
	// - consider rewriting the MAC address with the next hop address. it works
	// fine but it won't look like spoofing if we fix it.

	err := e.s.AddStaticNeighbor(e.nicID, protocol, ipv4.SourceAddress(), eth.SourceAddress())
	if err != nil {
		log.Printf("Failed to add static neighbor: %v", err)
	}
	e.Endpoint.DeliverNetworkPacket(protocol, pkt)
}
