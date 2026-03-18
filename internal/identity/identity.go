// Package identity maintains a concurrency-safe, in-memory cache of VM identity
// records keyed by tap interface name. It is the authoritative source for
// answering "who sent this packet?" during IMDS request handling.
//
// A record is populated when tapwatch reports a Created event for a tap
// interface and evicted on a Deleted event. The Lookup method performs three
// authenticity checks before returning a record:
//
//  1. The kernel ifindex must match the one recorded at population time.
//  2. The source MAC must match the netN entry in the VM's config file.
//  3. The QEMU process start time must still match /proc/{pid}/stat (PID-reuse
//     guard: detects a VM restart even before the DELLINK event arrives).
package identity

import (
	"errors"
	"net"

	"github.com/wyattanderson/pve-imds/internal/vmconfig"
	"github.com/wyattanderson/pve-imds/internal/vmproc"
)

// VMRecord is the fully verified identity of a VM tap interface.
type VMRecord struct {
	// Node is the Proxmox hostname (os.Hostname at startup).
	Node string

	// VMID is the numeric VM identifier parsed from the tap interface name.
	VMID int

	// NetIndex is the NIC index parsed from the tap interface name (the N in
	// tap{vmid}i{N}).
	NetIndex int

	// IfIndex is the kernel interface index recorded when the entry was
	// populated. Used to reject requests that arrive on a recycled ifname.
	IfIndex int32

	// Config is the parsed main section of /etc/pve/qemu-server/{vmid}.conf
	// as it existed when the tap interface came up (or was last reloaded).
	Config *vmconfig.VMConfig

	// ProcessInfo is the (PID, StartTime) pair of the QEMU process.
	ProcessInfo vmproc.ProcessInfo
}

// Provider is the interface consumed by the HTTP proxy layer to resolve VM
// identity. Depending on this interface (rather than *Resolver directly) lets
// proxy tests inject a fake without importing the full identity package.
type Provider interface {
	Lookup(ifname string, ifindex int32, srcMAC net.HardwareAddr) (*VMRecord, error)
}

// Sentinel errors returned by Resolver.Lookup. Callers should use errors.Is.
var (
	// ErrNotFound is returned when no cache entry exists for the ifname.
	ErrNotFound = errors.New("identity: interface not in cache")

	// ErrIfindexMismatch is returned when the supplied ifindex does not match
	// the one recorded at population time. This guards against a tap interface
	// being deleted and recreated with the same name but a different ifindex.
	ErrIfindexMismatch = errors.New("identity: ifindex mismatch")

	// ErrNetworkNotFound is returned when the config file has no netN entry
	// for the net_index encoded in the interface name.
	ErrNetworkNotFound = errors.New("identity: net device not found in config")

	// ErrMACMismatch is returned when the source MAC of the incoming packet
	// does not match the MAC recorded in the VM's config.
	ErrMACMismatch = errors.New("identity: source MAC does not match config")

	// ErrProcessChanged is returned when the QEMU process start time no longer
	// matches the cached value, indicating the VM was restarted.
	ErrProcessChanged = errors.New("identity: process start time changed (VM restarted?)")
)
