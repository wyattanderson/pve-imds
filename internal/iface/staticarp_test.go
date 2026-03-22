//go:build linux

package iface

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/veth"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// makeInboundIPv4Pkt builds a minimal ethernet+IPv4 packet buffer as it would
// arrive from the XDP path (payload-only, headers not yet consumed).
func makeInboundIPv4Pkt(t *testing.T, srcMAC, dstMAC tcpip.LinkAddress, srcIP, dstIP tcpip.Address) *stack.PacketBuffer {
	t.Helper()
	raw := make([]byte, header.EthernetMinimumSize+header.IPv4MinimumSize)
	eth := header.Ethernet(raw[:header.EthernetMinimumSize])
	eth.Encode(&header.EthernetFields{
		SrcAddr: srcMAC,
		DstAddr: dstMAC,
		Type:    header.IPv4ProtocolNumber,
	})
	ip4 := header.IPv4(raw[header.EthernetMinimumSize:])
	ip4.Encode(&header.IPv4Fields{
		SrcAddr:     srcIP,
		DstAddr:     dstIP,
		Protocol:    uint8(header.TCPProtocolNumber),
		TTL:         64,
		TotalLength: header.IPv4MinimumSize,
	})
	ip4.SetChecksum(^ip4.CalculateChecksum())
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
	t.Cleanup(pkt.DecRef)
	return pkt
}

func TestStaticARPEndpoint_LearnNeighbor(t *testing.T) {
	ep1, _ := veth.NewPair(1500, veth.DefaultBacklogSize)
	t.Cleanup(ep1.Close)

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	t.Cleanup(s.Close)

	const nicID = tcpip.NICID(1)
	// Wrap with ethernet.New so the NIC reports CapabilityResolutionRequired,
	// which causes the stack to populate linkAddrResolvers and allows
	// AddStaticNeighbor to succeed.
	sarp := NewStaticARPEndpoint(slog.Default(), ethernet.New(ep1), s, nicID)
	require.Nil(t, s.CreateNIC(nicID, sarp))
	require.Nil(t, s.EnableNIC(nicID))

	srcMAC := tcpip.LinkAddress("\xaa\xbb\xcc\xdd\xee\xff")
	dstMAC := tcpip.LinkAddress("\x00\x00\x00\x00\x00\x01")
	srcIP := tcpip.AddrFrom4([4]byte{169, 254, 1, 1})
	dstIP := tcpip.AddrFrom4([4]byte{169, 254, 169, 254})

	pkt := makeInboundIPv4Pkt(t, srcMAC, dstMAC, srcIP, dstIP)
	sarp.DeliverNetworkPacket(ipv4.ProtocolNumber, pkt)

	neighbors, tcpipErr := s.Neighbors(nicID, ipv4.ProtocolNumber)
	require.Nil(t, tcpipErr)

	found := false
	for _, n := range neighbors {
		if n.Addr == srcIP && n.LinkAddr == srcMAC {
			found = true
			break
		}
	}
	assert.True(t, found, "expected static neighbor %v -> %v; got %v", srcIP, srcMAC, neighbors)
}

// newSARPEndpoint is a test helper that creates a StaticARPEndpoint attached to
// a fresh veth pair. It returns the endpoint and the stack; both are registered
// for cleanup.
func newSARPEndpoint(t *testing.T) *Endpoint {
	t.Helper()
	ep1, _ := veth.NewPair(1500, veth.DefaultBacklogSize)
	t.Cleanup(ep1.Close)

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	t.Cleanup(s.Close)

	const nicID = tcpip.NICID(1)
	sarp := NewStaticARPEndpoint(slog.Default(), ethernet.New(ep1), s, nicID)
	require.Nil(t, s.CreateNIC(nicID, sarp))
	require.Nil(t, s.EnableNIC(nicID))
	return sarp
}

// addHeaderSrcMAC calls AddHeader on a minimal outbound packet and returns the
// source MAC encoded into the resulting ethernet frame.
func addHeaderSrcMAC(t *testing.T, sarp *Endpoint) tcpip.LinkAddress {
	t.Helper()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.EthernetMinimumSize,
	})
	t.Cleanup(pkt.DecRef)
	pkt.EgressRoute.LocalLinkAddress = tcpip.LinkAddress("\x11\x11\x11\x11\x11\x11") // placeholder
	pkt.EgressRoute.RemoteLinkAddress = tcpip.LinkAddress("\xaa\xbb\xcc\xdd\xee\xff")
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	sarp.AddHeader(pkt)
	return header.Ethernet(pkt.LinkHeader().Slice()).SourceAddress()
}

// TestStaticARPEndpoint_AddHeader_GatewayMAC verifies that when the VM routes
// packets via its default gateway (inbound dst = gateway MAC), outbound frames
// are sourced from that same gateway MAC so the VM's IP stack accepts them.
func TestStaticARPEndpoint_AddHeader_GatewayMAC(t *testing.T) {
	sarp := newSARPEndpoint(t)

	vmMAC := tcpip.LinkAddress("\xaa\xbb\xcc\xdd\xee\xff")
	gwMAC := tcpip.LinkAddress("\x00\x11\x22\x33\x44\x55")
	vmIP := tcpip.AddrFrom4([4]byte{169, 254, 1, 1})
	imdsIP := tcpip.AddrFrom4([4]byte{169, 254, 169, 254})

	sarp.DeliverNetworkPacket(ipv4.ProtocolNumber, makeInboundIPv4Pkt(t, vmMAC, gwMAC, vmIP, imdsIP))

	assert.Equal(t, gwMAC, addHeaderSrcMAC(t, sarp))
}

// TestStaticARPEndpoint_AddHeader_ARPPath verifies that when the VM discovered
// us via ARP and sends packets with dst = our NIC MAC, outbound frames are
// sourced from that same MAC.
func TestStaticARPEndpoint_AddHeader_ARPPath(t *testing.T) {
	sarp := newSARPEndpoint(t)

	vmMAC := tcpip.LinkAddress("\xaa\xbb\xcc\xdd\xee\xff")
	nicMAC := tcpip.LinkAddress("\x00\x00\x00\x00\x00\x02") // simulates tap NIC MAC after ARP
	vmIP := tcpip.AddrFrom4([4]byte{169, 254, 1, 1})
	imdsIP := tcpip.AddrFrom4([4]byte{169, 254, 169, 254})

	sarp.DeliverNetworkPacket(ipv4.ProtocolNumber, makeInboundIPv4Pkt(t, vmMAC, nicMAC, vmIP, imdsIP))

	assert.Equal(t, nicMAC, addHeaderSrcMAC(t, sarp))
}
