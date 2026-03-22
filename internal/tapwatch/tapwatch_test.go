package tapwatch

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadCapture reads base64-encoded netlink messages from path, one per line.
func loadCapture(t *testing.T, path string) []netlink.Message {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err, "open capture")
	defer f.Close() //nolint:errcheck

	var msgs []netlink.Message
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(line)
		require.NoError(t, err, "base64 decode")
		var m netlink.Message
		require.NoError(t, m.UnmarshalBinary(raw), "unmarshal message")
		msgs = append(msgs, m)
	}
	require.NoError(t, sc.Err(), "scan")
	return msgs
}

// collectingSink is an EventSink that appends events and cancels ctx once
// wantCount events have been received.
type collectingSink struct {
	events    []Event
	wantCount int
	cancel    context.CancelFunc
}

func (s *collectingSink) HandleLinkEvent(_ context.Context, e Event) {
	s.events = append(s.events, e)
	if len(s.events) >= s.wantCount {
		s.cancel()
	}
}

// runWatcher drives a Watcher with the given messages and collects events.
// It cancels the context after wantCount events have been received, then waits
// for Run to return.
func runWatcher(msgs []netlink.Message, wantCount int) []Event {
	i := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn := nltest.Dial(func(_ []netlink.Message) ([]netlink.Message, error) {
		if i >= len(msgs) {
			cancel()
			return nil, io.EOF
		}
		msg := msgs[i]
		i++
		return []netlink.Message{msg}, nil
	})

	w := New(conn, slog.Default())

	sink := &collectingSink{wantCount: wantCount, cancel: cancel}
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.Run(ctx, sink) //nolint:errcheck
	}()
	<-done
	return sink.events
}

// TestTwoInstanceLifecycle replays a capture of two VMs booting and shutting
// down and expects a Created then Deleted event for each tap interface.
func TestTwoInstanceLifecycle(t *testing.T) {
	msgs := loadCapture(t, "testdata/capture-two-instances.nl")

	events := runWatcher(msgs, 4)

	assert.Equal(t, []Event{
		{Type: Created, Name: "tap110i0", Index: 21},
		{Type: Created, Name: "tap111i0", Index: 22},
		{Type: Deleted, Name: "tap110i0", Index: 21},
		{Type: Deleted, Name: "tap111i0", Index: 22},
	}, events)
}

// TestSingleLifecycle replays capture.nl (one VM boot + shutdown) and expects
// exactly one Created then one Deleted event for the tap interface.
func TestSingleLifecycle(t *testing.T) {
	msgs := loadCapture(t, "testdata/capture-single-lifecycle.nl")

	events := runWatcher(msgs, 2)

	assert.Equal(t, []Event{
		{Type: Created, Name: "tap110i0", Index: 20},
		{Type: Deleted, Name: "tap110i0", Index: 20},
	}, events)
}

// makeSink returns a simple EventSink that collects events into a slice.
func makeSink() *collectingSink {
	_, cancel := context.WithCancel(context.Background())
	return &collectingSink{wantCount: 9999, cancel: cancel}
}

// TestScanEmitsTapInterfacesUp verifies that Scan emits Created events for
// tap interfaces that are up and skips everything else.
func TestScanEmitsTapInterfacesUp(t *testing.T) {
	w := New(nil, slog.Default())
	w.lister = func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 5, Name: "tap110i0", Flags: net.FlagUp},
			{Index: 6, Name: "tap111i1", Flags: net.FlagUp},
			{Index: 7, Name: "eth0", Flags: net.FlagUp},           // non-tap: skip
			{Index: 8, Name: "tap112i0", Flags: 0},                // down: skip
			{Index: 9, Name: "vmbr0", Flags: net.FlagUp},          // non-tap: skip
			{Index: 10, Name: "tapnotanumber", Flags: net.FlagUp}, // no digits: skip
		}, nil
	}

	sink := makeSink()
	require.NoError(t, w.Scan(context.Background(), sink))

	assert.Equal(t, []Event{
		{Type: Created, Name: "tap110i0", Index: 5},
		{Type: Created, Name: "tap111i1", Index: 6},
	}, sink.events)
}

// TestScanNoDoubleEmitAfterRun verifies that Scan marks interfaces as seen so
// that a subsequent Run does not re-emit Created for the same interface.
func TestScanNoDoubleEmitAfterRun(t *testing.T) {
	w := New(nil, slog.Default())
	w.lister = func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 21, Name: "tap110i0", Flags: net.FlagUp},
		}, nil
	}

	sink := makeSink()
	require.NoError(t, w.Scan(context.Background(), sink))
	require.Len(t, sink.events, 1)

	// Calling Scan again should not re-emit for the same interface.
	require.NoError(t, w.Scan(context.Background(), sink))
	assert.Len(t, sink.events, 1, "Scan must not re-emit for already-seen interface")
}

// TestScanEmpty verifies that Scan with no matching interfaces emits nothing.
func TestScanEmpty(t *testing.T) {
	w := New(nil, slog.Default())
	w.lister = func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 1, Name: "lo", Flags: net.FlagUp | net.FlagLoopback},
			{Index: 2, Name: "eth0", Flags: net.FlagUp},
		}, nil
	}

	sink := makeSink()
	require.NoError(t, w.Scan(context.Background(), sink))
	assert.Empty(t, sink.events)
}

// TestScanListerError verifies that Scan propagates errors from the lister.
func TestScanListerError(t *testing.T) {
	w := New(nil, slog.Default())
	w.lister = func() ([]net.Interface, error) {
		return nil, assert.AnError
	}

	sink := makeSink()
	assert.ErrorIs(t, w.Scan(context.Background(), sink), assert.AnError)
	assert.Empty(t, sink.events)
}
