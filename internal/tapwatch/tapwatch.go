// Package tapwatch distills the noisy RTNLGRP_LINK multicast stream into
// clean Created/Deleted lifecycle events for tap interfaces.
package tapwatch

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"regexp"

	"github.com/mdlayher/netlink"
	"go.uber.org/fx"
)

// tapIfaceRe matches Proxmox tap interface names: tap{vmid}i{netindex}.
var tapIfaceRe = regexp.MustCompile(`^tap\d+i\d+$`)

// Linux RTNETLINK constants not exported by the netlink package.
const (
	rtmNewLink = 16
	rtmDelLink = 17
	iflaIfname = 3
	iffUp      = 0x1
)

// ifInfomsg is the fixed-size header that precedes netlink attributes in
// RTM_NEWLINK / RTM_DELLINK messages (struct ifinfomsg in linux/rtnetlink.h).
type ifInfomsg struct {
	Family uint8
	_      uint8
	Type   uint16
	Index  int32
	Flags  uint32
	Change uint32
}

// EventType distinguishes tap interface lifecycle events.
type EventType int

const (
	// Created is emitted when a tap interface transitions to the up state.
	Created EventType = iota
	// Deleted is emitted when a tap interface is removed.
	Deleted
)

// Event describes a tap interface lifecycle transition.
type Event struct {
	Type  EventType
	Name  string // e.g. "tap110i0"
	Index int32  // kernel ifindex
}

type ifKey struct {
	name  string
	index int32
}

// Watcher distills RTNLGRP_LINK multicast messages into Created/Deleted events.
type Watcher struct {
	conn   *netlink.Conn
	seen   map[ifKey]struct{} // keys for which Created has been emitted
	log    *slog.Logger
	lister func() ([]net.Interface, error) // injectable for tests
}

// New creates a Watcher that reads from conn.
func New(conn *netlink.Conn, log *slog.Logger) *Watcher {
	return &Watcher{
		conn:   conn,
		seen:   make(map[ifKey]struct{}),
		log:    log,
		lister: net.Interfaces,
	}
}

// Scan enumerates existing network interfaces and emits a Created event for
// each tap interface matching tap{vmid}i{netindex} that is currently up.
// Call Scan before Run so that VMs already running when the daemon starts are
// reported before the live netlink stream begins. Scan updates w.seen so that
// Run will not re-emit Created for the same interfaces.
func (w *Watcher) Scan(ctx context.Context, sink EventSink) error {
	ifaces, err := w.lister()
	if err != nil {
		return err
	}
	for _, iface := range ifaces {
		if !tapIfaceRe.MatchString(iface.Name) {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		key := ifKey{name: iface.Name, index: int32(iface.Index)}
		if _, already := w.seen[key]; already {
			continue
		}
		w.seen[key] = struct{}{}
		ev := Event{Type: Created, Name: iface.Name, Index: int32(iface.Index)}
		w.log.DebugContext(ctx, "emitting startup event", "name", ev.Name, "index", ev.Index)
		sink.HandleLinkEvent(ctx, ev)
	}
	return nil
}

// EventSink receives tap interface lifecycle events.
type EventSink interface {
	HandleLinkEvent(context.Context, Event)
}

// MultiSink fans out a single HandleLinkEvent call to all registered sinks in
// the order they appear in the slice. Use it when multiple consumers need the
// same tap interface lifecycle events.
type MultiSink []EventSink

// HandleLinkEvent dispatches ev to all sinks in the slice.
func (ms MultiSink) HandleLinkEvent(ctx context.Context, ev Event) {
	for _, s := range ms {
		s.HandleLinkEvent(ctx, ev)
	}
}

// Run reads from the netlink connection until ctx is cancelled, calling
// sink for each Created or Deleted event. It closes conn when ctx is done
// so that a blocking Receive unblocks promptly.
func (w *Watcher) Run(ctx context.Context, sink EventSink) error {
	go func() { <-ctx.Done(); w.conn.Close() }() //nolint:errcheck

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		msgs, err := w.conn.Receive()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		for _, msg := range msgs {
			if ev, ok := w.process(msg); ok {
				w.log.DebugContext(ctx, "emitting event", "event", ev.Type, "name", ev.Name, "index", ev.Index)
				sink.HandleLinkEvent(ctx, ev)
			} else {
				w.log.DebugContext(ctx, "skipping message", "type", msg.Header.Type)
			}
		}
	}
}

// NewNetlinkConn opens a NETLINK_ROUTE socket subscribed to RTNLGRP_LINK.
func NewNetlinkConn() (*netlink.Conn, error) {
	conn, err := netlink.Dial(0, nil) // 0 = NETLINK_ROUTE
	if err != nil {
		return nil, fmt.Errorf("dial netlink: %w", err)
	}
	if err := conn.JoinGroup(1); err != nil { // 1 = RTNLGRP_LINK
		conn.Close() //nolint:errcheck
		return nil, fmt.Errorf("join RTNLGRP_LINK: %w", err)
	}
	return conn, nil
}

// RegisterParams are the dependencies for Register. Sinks are collected from
// all providers that contribute to the "event_sinks" value group, so any
// package can register a new EventSink without touching this call site.
type RegisterParams struct {
	fx.In

	LC      fx.Lifecycle
	Watcher *Watcher
	Sinks   []EventSink `group:"event_sinks"`
	Log     *slog.Logger
}

// Register is an fx.Invoke target that wires the Watcher into the fx lifecycle.
// It builds a MultiSink from all registered EventSinks and runs Scan + Run.
func Register(p RegisterParams) {
	sink := MultiSink(p.Sinks)
	ctx, cancel := context.WithCancel(context.Background())
	p.LC.Append(fx.Hook{
		OnStart: func(_ context.Context) error {
			p.Log.Info("starting tap interface watcher")
			if err := p.Watcher.Scan(ctx, sink); err != nil {
				cancel()
				return fmt.Errorf("initial interface scan: %w", err)
			}
			go func() {
				if err := p.Watcher.Run(ctx, sink); err != nil {
					p.Log.Error("tap watcher exited", "err", err)
				}
			}()
			return nil
		},
		OnStop: func(_ context.Context) error {
			p.Log.Info("stopping tap interface watcher")
			cancel()
			return nil
		},
	})
}

// process inspects a single netlink message and returns the corresponding
// Event if it represents a tap interface lifecycle transition.
func (w *Watcher) process(msg netlink.Message) (Event, bool) {
	hdrSize := binary.Size(ifInfomsg{})
	if len(msg.Data) < hdrSize {
		return Event{}, false
	}

	var info ifInfomsg
	if err := binary.Read(bytes.NewReader(msg.Data[:hdrSize]), binary.LittleEndian, &info); err != nil {
		return Event{}, false
	}

	attrs, err := netlink.NewAttributeDecoder(msg.Data[hdrSize:])
	if err != nil {
		return Event{}, false
	}

	var name string
	for attrs.Next() {
		if attrs.Type() == iflaIfname {
			name = attrs.String()
			break
		}
	}

	if name == "" {
		return Event{}, false
	}

	key := ifKey{name: name, index: info.Index}
	up := info.Flags&iffUp != 0

	switch msg.Header.Type {
	case rtmNewLink:
		if up {
			if _, already := w.seen[key]; !already {
				w.seen[key] = struct{}{}
				return Event{Type: Created, Name: name, Index: info.Index}, true
			}
		}
	case rtmDelLink:
		if !up {
			if _, exists := w.seen[key]; exists {
				delete(w.seen, key)
				return Event{Type: Deleted, Name: name, Index: info.Index}, true
			}
		}
	}

	return Event{}, false
}
