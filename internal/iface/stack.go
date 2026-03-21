//go:build linux

package iface

import (
	"fmt"
	"log/slog"
	"strings"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
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

	if tcpipErr := s.CreateNIC(nicID, NewStaticARPEndpoint(log, le, s, nicID)); tcpipErr != nil {
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
