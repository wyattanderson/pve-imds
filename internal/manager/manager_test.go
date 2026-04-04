package manager

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyattanderson/pve-imds/internal/tapwatch"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	log := slog.Default()
	m := New(log, stubRuntimeFactory)
	return m
}

// startLoop starts m.run in a goroutine and registers cleanup.
func startLoop(t *testing.T, m *Manager) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); m.run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	return ctx
}

// blockingRuntime closes started when Run is entered, then blocks on ctx.
// If stopped is non-nil it is closed when Run returns.
type blockingRuntime struct {
	started chan struct{}
	stopped chan struct{}
}

func (r *blockingRuntime) Run(ctx context.Context) error {
	close(r.started)
	<-ctx.Done()
	if r.stopped != nil {
		close(r.stopped)
	}
	return nil
}

func TestStartStop(t *testing.T) {
	m := newTestManager(t)

	started := make(chan struct{})
	stopped := make(chan struct{})
	m.factory = func(_ int32, _ string) InterfaceRuntime {
		return &blockingRuntime{started: started, stopped: stopped}
	}

	ctx := startLoop(t, m)

	m.HandleLinkEvent(ctx, tapwatch.Event{Type: tapwatch.Created, Name: "tap100i0", Index: 10})
	<-started // runtime is running

	m.HandleLinkEvent(ctx, tapwatch.Event{Type: tapwatch.Deleted, Name: "tap100i0", Index: 10})

	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("runtime was not stopped within timeout")
	}
}

func TestDeleteDuringStart(t *testing.T) {
	m := newTestManager(t)

	started := make(chan struct{})
	stopped := make(chan struct{})
	m.factory = func(_ int32, _ string) InterfaceRuntime {
		return &blockingRuntime{started: started, stopped: stopped}
	}

	ctx := startLoop(t, m)

	m.HandleLinkEvent(ctx, tapwatch.Event{Type: tapwatch.Created, Name: "tap100i0", Index: 10})
	<-started // runtime is now blocking in Run

	// Send delete while runtime is running.
	m.HandleLinkEvent(ctx, tapwatch.Event{Type: tapwatch.Deleted, Name: "tap100i0", Index: 10})

	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("runtime was not stopped within timeout after delete during run")
	}
}

func TestStopAllOnContextCancel(t *testing.T) {
	m := newTestManager(t)

	type startedEntry struct{ name string }
	allStarted := make(chan startedEntry, 10)
	m.factory = func(_ int32, name string) InterfaceRuntime {
		started := make(chan struct{})
		go func() { <-started; allStarted <- startedEntry{name} }()
		return &blockingRuntime{started: started}
	}

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() { defer close(loopDone); m.run(ctx) }()

	m.HandleLinkEvent(ctx, tapwatch.Event{Type: tapwatch.Created, Name: "tap100i0", Index: 10})
	m.HandleLinkEvent(ctx, tapwatch.Event{Type: tapwatch.Created, Name: "tap101i0", Index: 11})

	// Wait for both to start.
	<-allStarted
	<-allStarted

	cancel()
	<-loopDone

	if len(m.active) != 0 {
		t.Fatalf("expected all runtimes stopped, %d still active", len(m.active))
	}
}

func TestHandleLinkEventDoesNotBlock(t *testing.T) {
	m := newTestManager(t)
	// Do NOT start the event loop — events pile up in the buffer.

	// Fill the buffer.
	for range 64 {
		m.events <- tapwatch.Event{Type: tapwatch.Created, Name: "tap100i0", Index: 10}
	}

	// A cancelled context should cause HandleLinkEvent to take the Done arm
	// rather than blocking.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		m.HandleLinkEvent(ctx, tapwatch.Event{Type: tapwatch.Created, Name: "tap999i0", Index: 99})
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("HandleLinkEvent blocked on full channel with cancelled context")
	}
}

func TestStartDuplicateIgnored(t *testing.T) {
	m := newTestManager(t)

	var callCount atomic.Int32
	m.factory = func(_ int32, _ string) InterfaceRuntime {
		callCount.Add(1)
		return &blockingRuntime{started: make(chan struct{})}
	}

	ctx := startLoop(t, m)

	m.HandleLinkEvent(ctx, tapwatch.Event{Type: tapwatch.Created, Name: "tap100i0", Index: 10})
	m.HandleLinkEvent(ctx, tapwatch.Event{Type: tapwatch.Created, Name: "tap100i0", Index: 10})

	// Let events drain.
	time.Sleep(20 * time.Millisecond)

	if n := callCount.Load(); n != 1 {
		t.Fatalf("expected factory called once, got %d", n)
	}
}

func TestDeleteUnknownIgnored(t *testing.T) {
	m := newTestManager(t)
	ctx := startLoop(t, m)

	// Should not panic.
	m.HandleLinkEvent(ctx, tapwatch.Event{Type: tapwatch.Deleted, Name: "tap999i0", Index: 99})

	time.Sleep(20 * time.Millisecond) // let event drain
}
