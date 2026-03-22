package identity

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"
	"sync"

	"github.com/spf13/afero"

	"github.com/wyattanderson/pve-imds/internal/tapwatch"
	"github.com/wyattanderson/pve-imds/internal/vmconfig"
)

// tapIfaceRe matches and captures vmid and netIndex from tap interface names.
var tapIfaceRe = regexp.MustCompile(`^tap(\d+)i(\d+)$`)

// Resolver maintains the in-memory identity cache.
//
// It implements tapwatch.EventSink: Created events trigger populate and Deleted
// events trigger invalidate. The Stage 4 file watcher calls ReloadConfig
// directly when it detects file-system changes.
type Resolver struct {
	fs   afero.Fs
	log  *slog.Logger
	node string

	mu            sync.RWMutex
	entries       map[string]*entry // key: ifname e.g. "tap100i0"
	vmidToIfnames map[int][]string  // secondary index for config reloads
}

// New returns a Resolver that reads VM config files from fs. It records the
// local hostname as the node name; if that fails, New returns an error.
func New(fs afero.Fs, log *slog.Logger) (*Resolver, error) {
	node, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("identity: resolve hostname: %w", err)
	}
	return &Resolver{
		fs:            fs,
		log:           log,
		node:          node,
		entries:       make(map[string]*entry),
		vmidToIfnames: make(map[int][]string),
	}, nil
}

// Lookup verifies and returns the VM identity for an incoming packet.
//
// It checks, in order:
//  1. ifname is in the cache.
//  2. ifindex matches the one recorded at population time.
//  3. srcMAC matches the netN entry in the parsed config.
//
// All three checks must pass; any failure returns a sentinel error.
func (r *Resolver) Lookup(ifname string, ifindex int32, srcMAC net.HardwareAddr) (*VMRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	e, ok := r.entries[ifname]
	if !ok {
		return nil, ErrNotFound
	}

	if e.ifindex != ifindex {
		return nil, ErrIfindexMismatch
	}

	dev, ok := e.config.Networks[e.netIndex]
	if !ok {
		return nil, ErrNetworkNotFound
	}

	if !bytes.Equal(dev.MAC, srcMAC) {
		return nil, ErrMACMismatch
	}

	return &VMRecord{
		Node:     r.node,
		VMID:     e.vmid,
		NetIndex: e.netIndex,
		IfIndex:  e.ifindex,
		Config:   e.config,
	}, nil
}

// ReloadConfig re-reads the config file for vmid and updates all cache entries
// that share it. Called by the Stage 4 file watcher on IN_CLOSE_WRITE for a
// .conf file. A parse failure leaves the existing cached config intact.
func (r *Resolver) ReloadConfig(vmid int) {
	raw, err := afero.ReadFile(r.fs, fmt.Sprintf("/etc/pve/qemu-server/%d.conf", vmid))
	if err != nil {
		r.log.Warn("identity: reload config: read failed", "vmid", vmid, "err", err)
		return
	}
	cfg, err := vmconfig.ParseConfig(raw)
	if err != nil {
		r.log.Warn("identity: reload config: parse failed", "vmid", vmid, "err", err)
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ifname := range r.vmidToIfnames[vmid] {
		if e, ok := r.entries[ifname]; ok {
			e.config = cfg
		}
	}
}

// HandleLinkEvent implements tapwatch.EventSink.
func (r *Resolver) HandleLinkEvent(ctx context.Context, ev tapwatch.Event) {
	switch ev.Type {
	case tapwatch.Created:
		if err := r.populate(ctx, ev.Name, ev.Index); err != nil {
			r.log.WarnContext(ctx, "identity: populate failed", "ifname", ev.Name, "err", err)
		}
	case tapwatch.Deleted:
		r.invalidate(ev.Name)
	}
}

// populate reads the VM config for the given tap interface and inserts an entry
// into the cache. It is safe to call concurrently.
func (r *Resolver) populate(ctx context.Context, ifname string, ifindex int32) error {
	vmid, netIndex, err := parseIfname(ifname)
	if err != nil {
		return err
	}

	raw, err := afero.ReadFile(r.fs, fmt.Sprintf("/etc/pve/qemu-server/%d.conf", vmid))
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	cfg, err := vmconfig.ParseConfig(raw)
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	r.log.DebugContext(ctx, "identity: populating cache entry", "ifname", ifname, "vmid", vmid)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[ifname] = &entry{
		vmid:     vmid,
		netIndex: netIndex,
		ifindex:  ifindex,
		config:   cfg,
	}
	r.addIfname(vmid, ifname)

	return nil
}

// RecordByName returns the cached VMRecord for ifname, verifying that the
// kernel ifindex still matches the one recorded at population time. This guards
// against a tap interface being deleted and recreated (with a new VM) before
// the old per-interface Runtime has been torn down.
//
// Source MAC is not checked because it is not available at the HTTP handler layer.
func (r *Resolver) RecordByName(ifname string, ifindex int32) (*VMRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[ifname]
	if !ok {
		return nil, ErrNotFound
	}
	if e.ifindex != ifindex {
		return nil, ErrIfindexMismatch
	}
	return &VMRecord{
		Node:     r.node,
		VMID:     e.vmid,
		NetIndex: e.netIndex,
		IfIndex:  e.ifindex,
		Config:   e.config,
	}, nil
}

// invalidate removes the cache entry for ifname, if present.
func (r *Resolver) invalidate(ifname string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[ifname]
	if !ok {
		return
	}
	r.log.Debug("identity: evicting cache entry", "ifname", ifname, "vmid", e.vmid)
	delete(r.entries, ifname)
	r.removeIfname(e.vmid, ifname)
}

// invalidateByVMID evicts all cache entries for vmid. Called by the file
// watcher when a config file is removed (VM deleted or decommissioned).
func (r *Resolver) invalidateByVMID(vmid int) {
	r.mu.RLock()
	ifnames := slices.Clone(r.vmidToIfnames[vmid])
	r.mu.RUnlock()
	for _, ifname := range ifnames {
		r.invalidate(ifname)
	}
}

// parseIfname extracts vmid and netIndex from a tap interface name of the form
// tap{vmid}i{netIndex}.
func parseIfname(name string) (vmid, netIndex int, err error) {
	m := tapIfaceRe.FindStringSubmatch(name)
	if m == nil {
		return 0, 0, fmt.Errorf("identity: %q is not a tap interface name", name)
	}
	vmid, _ = strconv.Atoi(m[1])
	netIndex, _ = strconv.Atoi(m[2])
	return vmid, netIndex, nil
}
