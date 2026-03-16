//go:build linux

package xdp

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/veth"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
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
	defer pkt.DecRef()

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
