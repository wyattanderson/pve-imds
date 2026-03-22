//go:build linux

// Package xdp manages the AF_XDP redirect program that intercepts IMDS traffic.
package xdp

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
)

// LoadAndAttach loads the XDP redirect program, attaches it to iface,
// and registers sockfd in the XSKMAP. Returns a cleanup func.
func LoadAndAttach(sockfd int, iface *net.Interface) (func(), error) {
	var objs xdp_redirectObjects
	if err := loadXdp_redirectObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load XDP objects: %w", err)
	}

	attached, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpRedirectProg,
		Interface: iface.Index,
	})
	if err != nil {
		objs.Close() //nolint:errcheck
		return nil, fmt.Errorf("attach XDP to %s: %w", iface.Name, err)
	}

	key, val := uint32(0), uint32(sockfd)
	if err := objs.XsksMap.Update(&key, &val, 0); err != nil {
		attached.Close() //nolint:errcheck
		objs.Close()     //nolint:errcheck
		return nil, fmt.Errorf("update XSKMAP: %w", err)
	}

	return func() { attached.Close(); objs.Close() }, nil //nolint:errcheck
}
