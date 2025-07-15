package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"xdp-packet-monitor/pkg/redirect"
	"xdp-packet-monitor/pkg/staticarp"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/xdp"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func main() {
	var ifaceName, ipAddr string
	flag.StringVar(&ifaceName, "interface", "", "Network interface name to bind AF_XDP socket to")
	flag.StringVar(&ipAddr, "ip", "", "IP address with prefix (e.g., 192.168.1.100/24)")
	flag.Parse()

	if ifaceName == "" {
		log.Fatal("Please specify an interface name using -interface flag")
	}

	if ipAddr == "" {
		log.Fatal("Please specify an IP address using -ip flag")
	}

	log.Printf("Starting XDP packet monitor on interface %s with IP %s", ifaceName, ipAddr)

	// Parse IP address with prefix using standard net package
	ip, ipNet, err := net.ParseCIDR(ipAddr)
	if err != nil {
		log.Fatalf("Failed to parse IP address %s: %v", ipAddr, err)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		log.Fatalf("Only IPv4 addresses are supported: %v", ip)
	}

	l, _ := ipNet.Mask.Size()
	addrWithPrefix := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFrom4Slice(ip4),
		PrefixLen: l,
	}

	// Get interface index
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", ifaceName, err)
	}

	// Create AF_XDP socket
	sockfd, err := syscall.Socket(unix.AF_XDP, syscall.SOCK_RAW, 0)
	if err != nil {
		log.Fatalf("Failed to create AF_XDP socket: %v", err)
	}

	cleanup, err := redirect.LoadAndAttach(sockfd, iface)
	if err != nil {
		log.Fatalf("Failed to load and attach eBPF program: %v", err)
	}
	defer cleanup()

	addr, err := tcpip.ParseMACAddress(iface.HardwareAddr.String())
	if err != nil {
		log.Fatalf("Failed to parse MAC address: %v", err)
	}

	// Create XDP link endpoint
	le, err := xdp.New(&xdp.Options{
		FD:                sockfd,
		Address:           addr,
		Bind:              true,
		InterfaceIndex:    iface.Index,
		RXChecksumOffload: true,
	})
	if err != nil {
		log.Fatalf("Failed to create XDP link endpoint: %v", err)
	}

	// Create network stack
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		HandleLocal:        true,
	})

	nicID := tcpip.NICID(1)

	sarp := staticarp.NewEndpoint(le, s, nicID)
	// Create sniffer and enable packet logging
	// sn := sniffer.New(sarp)
	// sniffer.LogPackets.Store(1)

	// Create and enable NIC
	if err := s.CreateNIC(nicID, sarp); err != nil {
		log.Fatalf("Failed to create NIC: %v", err)
	}
	if err := s.EnableNIC(nicID); err != nil {
		log.Fatalf("Failed to enable NIC: %v", err)
	}
	// s.SetPromiscuousMode(nicID, true)
	// s.SetSpoofing(nicID, true)

	// Add protocol address to the NIC
	var protocol tcpip.NetworkProtocolNumber
	if addrWithPrefix.Address.Len() == 4 {
		protocol = ipv4.ProtocolNumber
	} else {
		protocol = ipv6.ProtocolNumber
	}
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          protocol,
		AddressWithPrefix: addrWithPrefix,
	}
	if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		log.Fatalf("Failed to add protocol address: %v", err)
	}

	subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice([]byte(strings.Repeat("\x00", addrWithPrefix.Address.Len()))), tcpip.MaskFrom(strings.Repeat("\x00", addrWithPrefix.Address.Len())))
	if err != nil {
		log.Fatalf("Failed to create subnet: %v", err)
	}

	log.Printf("Added protocol address %s to NIC with subnet %s", protocolAddr, subnet)

	route := tcpip.Route{
		Destination: subnet,
		NIC:         nicID,
	}
	s.SetRouteTable([]tcpip.Route{route})

	listener, err := gonet.ListenTCP(s, tcpip.FullAddress{Addr: addrWithPrefix.Address, Port: uint16(80)}, protocol)
	if err != nil {
		log.Fatalf("Failed to listen on TCP port 80: %v", err)
	}
	defer listener.Close()

	handler := http.NewServeMux()
	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, World!"))
	})

	server := &http.Server{
		Handler: handler,
	}

	go server.Serve(listener)

	log.Printf("XDP packet monitor started successfully")
	log.Printf("Waiting for packets on interface %s...", ifaceName)
	log.Printf("Press Ctrl+C to stop")

	// Set up signal handling for graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Wait for shutdown signal
	<-ctx.Done()
	log.Printf("Shutting down XDP packet monitor...")

	// Clean up
	s.Close()
	if err := syscall.Close(sockfd); err != nil {
		log.Printf("Error closing socket: %v", err)
	}

	log.Printf("XDP packet monitor stopped")
}
