package tapwatch

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
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
	defer f.Close()

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
	conn := nltest.Dial(func(_ []netlink.Message) ([]netlink.Message, error) {
		if i >= len(msgs) {
			return nil, io.EOF
		}
		msg := msgs[i]
		i++
		return []netlink.Message{msg}, nil
	})

	w := New(conn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
