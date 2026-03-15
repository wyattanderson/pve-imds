// Package tapwatch distills the noisy RTNLGRP_LINK multicast stream into
// clean Created/Deleted lifecycle events for tap interfaces.
package tapwatch

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"

	"github.com/mdlayher/netlink"
)

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
	Created EventType = iota
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
	conn *netlink.Conn
	seen map[ifKey]struct{} // keys for which Created has been emitted
	log  *slog.Logger
}

// New creates a Watcher that reads from conn.
func New(conn *netlink.Conn, log *slog.Logger) *Watcher {
	return &Watcher{
		conn: conn,
		seen: make(map[ifKey]struct{}),
		log:  log,
	}
}

// EventSink receives tap interface lifecycle events.
type EventSink interface {
	HandleLinkEvent(context.Context, Event)
}

// Run reads from the netlink connection until ctx is cancelled, calling
// sink for each Created or Deleted event. It closes conn when ctx is done
// so that a blocking Receive unblocks promptly.
func (w *Watcher) Run(ctx context.Context, sink EventSink) error {
	go func() { <-ctx.Done(); w.conn.Close() }()

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
		w.log.DebugContext(ctx, "received netlink messages", "count", len(msgs))
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
