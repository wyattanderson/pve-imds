//go:build integration

package identity

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spyResolver records calls made by the FileWatcher. It satisfies resolverSink.
type spyResolver struct {
	mu               sync.Mutex
	reloadConfigs    []int
	reloadProcesses  []int
	invalidatedVMIDs []int
}

func (s *spyResolver) ReloadConfig(vmid int) {
	s.mu.Lock()
	s.reloadConfigs = append(s.reloadConfigs, vmid)
	s.mu.Unlock()
}

func (s *spyResolver) ReloadProcess(vmid int) {
	s.mu.Lock()
	s.reloadProcesses = append(s.reloadProcesses, vmid)
	s.mu.Unlock()
}

func (s *spyResolver) invalidateByVMID(vmid int) {
	s.mu.Lock()
	s.invalidatedVMIDs = append(s.invalidatedVMIDs, vmid)
	s.mu.Unlock()
}

func (s *spyResolver) hasReloadConfig(vmid int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.reloadConfigs {
		if v == vmid {
			return true
		}
	}
	return false
}

func (s *spyResolver) hasReloadProcess(vmid int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.reloadProcesses {
		if v == vmid {
			return true
		}
	}
	return false
}

func (s *spyResolver) hasInvalidated(vmid int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.invalidatedVMIDs {
		if v == vmid {
			return true
		}
	}
	return false
}

// startWatcher creates a FileWatcher watching the given temp dirs and starts
// Run in a goroutine. Returns the watcher and a cancel func to stop it.
func startWatcher(t *testing.T, spy *spyResolver, confDir, pidDir string) context.CancelFunc {
	t.Helper()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	fw, err := newFileWatcherWithDirs(spy, log, confDir, pidDir)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel() })
	go func() { _ = fw.Run(ctx) }()
	return cancel
}

const (
	eventTimeout = 2 * time.Second
	pollInterval = 25 * time.Millisecond
)

// TestIntegrationConfWrite verifies that writing a .conf file triggers
// ReloadConfig with the correct VMID.
func TestIntegrationConfWrite(t *testing.T) {
	confDir := t.TempDir()
	pidDir := t.TempDir()
	spy := &spyResolver{}
	startWatcher(t, spy, confDir, pidDir)

	const vmid = 42
	path := filepath.Join(confDir, fmt.Sprintf("%d.conf", vmid))
	require.NoError(t, os.WriteFile(path, []byte("name: vm42\n"), 0644))

	require.Eventually(t, func() bool { return spy.hasReloadConfig(vmid) },
		eventTimeout, pollInterval, "ReloadConfig(%d) not called after conf write", vmid)
}

// TestIntegrationConfDelete verifies that removing a .conf file triggers
// invalidateByVMID with the correct VMID.
func TestIntegrationConfDelete(t *testing.T) {
	confDir := t.TempDir()
	pidDir := t.TempDir()
	spy := &spyResolver{}
	startWatcher(t, spy, confDir, pidDir)

	const vmid = 99
	path := filepath.Join(confDir, fmt.Sprintf("%d.conf", vmid))
	require.NoError(t, os.WriteFile(path, []byte("name: vm99\n"), 0644))

	// Wait for the write event to be processed before deleting.
	require.Eventually(t, func() bool { return spy.hasReloadConfig(vmid) },
		eventTimeout, pollInterval)

	require.NoError(t, os.Remove(path))

	require.Eventually(t, func() bool { return spy.hasInvalidated(vmid) },
		eventTimeout, pollInterval, "invalidateByVMID(%d) not called after conf delete", vmid)
}

// TestIntegrationPIDCreate verifies that creating a .pid file triggers
// ReloadProcess with the correct VMID (the PID-after-NEWLINK race path).
func TestIntegrationPIDCreate(t *testing.T) {
	confDir := t.TempDir()
	pidDir := t.TempDir()
	spy := &spyResolver{}
	startWatcher(t, spy, confDir, pidDir)

	const vmid = 200
	path := filepath.Join(pidDir, fmt.Sprintf("%d.pid", vmid))
	require.NoError(t, os.WriteFile(path, []byte("12345\n"), 0644))

	require.Eventually(t, func() bool { return spy.hasReloadProcess(vmid) },
		eventTimeout, pollInterval, "ReloadProcess(%d) not called after pid create", vmid)
}

// TestIntegrationPIDRemoveNoAction verifies that removing a .pid file does NOT
// trigger any resolver call (tapwatch handles removal via DELLINK).
func TestIntegrationPIDRemoveNoAction(t *testing.T) {
	confDir := t.TempDir()
	pidDir := t.TempDir()
	spy := &spyResolver{}
	startWatcher(t, spy, confDir, pidDir)

	const vmid = 300
	path := filepath.Join(pidDir, fmt.Sprintf("%d.pid", vmid))
	require.NoError(t, os.WriteFile(path, []byte("54321\n"), 0644))

	// Wait for the write/create event to settle.
	require.Eventually(t, func() bool { return spy.hasReloadProcess(vmid) },
		eventTimeout, pollInterval)

	require.NoError(t, os.Remove(path))

	// Give the watcher time to process any spurious events, then assert no
	// invalidation occurred.
	time.Sleep(200 * time.Millisecond)
	spy.mu.Lock()
	assert.NotContains(t, spy.invalidatedVMIDs, vmid, "pid Remove must not trigger invalidation")
	spy.mu.Unlock()
}
