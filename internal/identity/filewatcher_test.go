package identity

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wyattanderson/pve-imds/internal/tapwatch"
	"github.com/wyattanderson/pve-imds/internal/vmproc"
)

// newFW builds a FileWatcher backed by a real resolver (MemMapFs) but without
// starting an actual fsnotify watch — the watcher field is nil because unit
// tests call handleEvent directly.
func newFW(t *testing.T) (*FileWatcher, *testEnv) {
	t.Helper()
	env := newTestEnv(t)
	fw := &FileWatcher{
		resolver: env.resolver,
		log:      slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}
	return fw, env
}

// confEvent builds an fsnotify event for a .conf file in the production dir.
func confEvent(vmid int, op fsnotify.Op) fsnotify.Event {
	return fsnotify.Event{
		Name: fmt.Sprintf("%s/%d.conf", defaultConfDir, vmid),
		Op:   op,
	}
}

// pidEvent builds an fsnotify event for a .pid file in the production dir.
func pidEvent(vmid int, op fsnotify.Op) fsnotify.Event {
	return fsnotify.Event{
		Name: fmt.Sprintf("%s/%d.pid", defaultPIDDir, vmid),
		Op:   op,
	}
}

// TestHandleEventConfWrite verifies that a Write event on a .conf file causes
// ReloadConfig to update the cached config name.
func TestHandleEventConfWrite(t *testing.T) {
	fw, env := newFW(t)
	env.addVM(t, vm100)
	env.populate(t, vm100)

	// Overwrite the config with a new name.
	confPath := fmt.Sprintf("/etc/pve/qemu-server/%d.conf", vm100.vmid)
	updated := fmt.Sprintf("name: renamed\nostype: l26\nnet0: virtio=%s,bridge=vmbr0\n", vm100.mac)
	require.NoError(t, afero.WriteFile(env.configFS, confPath, []byte(updated), 0644))

	fw.handleEvent(confEvent(vm100.vmid, fsnotify.Write))

	env.resolver.mu.RLock()
	e := env.resolver.entries[vm100.ifname]
	env.resolver.mu.RUnlock()
	require.NotNil(t, e)
	assert.Equal(t, "renamed", e.config.Name)
}

// TestHandleEventConfCreate verifies that a Create event (atomic rename write)
// also triggers ReloadConfig.
func TestHandleEventConfCreate(t *testing.T) {
	fw, env := newFW(t)
	env.addVM(t, vm100)
	env.populate(t, vm100)

	confPath := fmt.Sprintf("/etc/pve/qemu-server/%d.conf", vm100.vmid)
	updated := fmt.Sprintf("name: created\nostype: l26\nnet0: virtio=%s,bridge=vmbr0\n", vm100.mac)
	require.NoError(t, afero.WriteFile(env.configFS, confPath, []byte(updated), 0644))

	fw.handleEvent(confEvent(vm100.vmid, fsnotify.Create))

	env.resolver.mu.RLock()
	e := env.resolver.entries[vm100.ifname]
	env.resolver.mu.RUnlock()
	require.NotNil(t, e)
	assert.Equal(t, "created", e.config.Name)
}

// TestHandleEventConfRemove verifies that a Remove event on a .conf file
// evicts all cache entries for that VMID.
func TestHandleEventConfRemove(t *testing.T) {
	fw, env := newFW(t)
	env.addVM(t, vm100)
	env.populate(t, vm100)

	fw.handleEvent(confEvent(vm100.vmid, fsnotify.Remove))

	env.resolver.mu.RLock()
	_, ok := env.resolver.entries[vm100.ifname]
	env.resolver.mu.RUnlock()
	assert.False(t, ok, "entry should be evicted after conf Remove")
}

// TestHandleEventConfRename verifies that a Rename event (file moved out of
// directory) also evicts the cache entry.
func TestHandleEventConfRename(t *testing.T) {
	fw, env := newFW(t)
	env.addVM(t, vm100)
	env.populate(t, vm100)

	fw.handleEvent(confEvent(vm100.vmid, fsnotify.Rename))

	env.resolver.mu.RLock()
	_, ok := env.resolver.entries[vm100.ifname]
	env.resolver.mu.RUnlock()
	assert.False(t, ok, "entry should be evicted after conf Rename")
}

// TestHandleEventPIDCreate verifies that a Create event on a .pid file (the
// common case: PID file arrives after the tap interface is already up) fills
// in a zero-valued ProcessInfo in the cache entry.
func TestHandleEventPIDCreate(t *testing.T) {
	fw, env := newFW(t)

	// Write config but NOT the pid/stat files, then populate (should succeed
	// with zero ProcessInfo because pid file is absent).
	confPath := fmt.Sprintf("/etc/pve/qemu-server/%d.conf", vm100.vmid)
	require.NoError(t, afero.WriteFile(env.configFS, confPath,
		[]byte(confContent(vm100.vmid, vm100.netIndex, vm100.mac)), 0644))

	env.resolver.HandleLinkEvent(testCtx(), tapwatchCreatedEvent(vm100))

	// Entry should exist with zero ProcessInfo.
	env.resolver.mu.RLock()
	e := env.resolver.entries[vm100.ifname]
	env.resolver.mu.RUnlock()
	require.NotNil(t, e, "entry must be in cache even with missing pid file")
	assert.Zero(t, e.processInfo.PID)

	// Now write the PID and stat files and fire the Create event.
	pidPath := fmt.Sprintf("/var/run/qemu-server/%d.pid", vm100.vmid)
	require.NoError(t, afero.WriteFile(env.procFS, pidPath,
		fmt.Appendf(nil, "%d\n", vm100.pid), 0644))
	statPath := fmt.Sprintf("/proc/%d/stat", vm100.pid)
	require.NoError(t, afero.WriteFile(env.procFS, statPath,
		[]byte(statLine(vm100.pid, vm100.startTime)), 0644))

	fw.handleEvent(pidEvent(vm100.vmid, fsnotify.Create))

	env.resolver.mu.RLock()
	e = env.resolver.entries[vm100.ifname]
	env.resolver.mu.RUnlock()
	require.NotNil(t, e)
	assert.Equal(t, vm100.pid, e.processInfo.PID)
	assert.Equal(t, vm100.startTime, e.processInfo.StartTime)
}

// TestHandleEventPIDWrite verifies that a Write event on a .pid file also
// triggers a process reload (covers cases where PVE updates the PID file).
func TestHandleEventPIDWrite(t *testing.T) {
	fw, env := newFW(t)
	env.addVM(t, vm100)
	env.populate(t, vm100)

	// Update to a new PID.
	newPID, newStart := 9999, uint64(77777777)
	pidPath := fmt.Sprintf("/var/run/qemu-server/%d.pid", vm100.vmid)
	require.NoError(t, afero.WriteFile(env.procFS, pidPath,
		fmt.Appendf(nil, "%d\n", newPID), 0644))
	statPath := fmt.Sprintf("/proc/%d/stat", newPID)
	require.NoError(t, afero.WriteFile(env.procFS, statPath,
		[]byte(statLine(newPID, newStart)), 0644))

	fw.handleEvent(pidEvent(vm100.vmid, fsnotify.Write))

	env.resolver.mu.RLock()
	e := env.resolver.entries[vm100.ifname]
	env.resolver.mu.RUnlock()
	require.NotNil(t, e)
	assert.Equal(t, newPID, e.processInfo.PID)
	assert.Equal(t, newStart, e.processInfo.StartTime)
}

// TestHandleEventPIDRemove verifies that a Remove event on a .pid file is
// a no-op (tapwatch handles VM removal via DELLINK).
func TestHandleEventPIDRemove(t *testing.T) {
	fw, env := newFW(t)
	env.addVM(t, vm100)
	env.populate(t, vm100)

	fw.handleEvent(pidEvent(vm100.vmid, fsnotify.Remove))

	// Entry should still be present.
	env.resolver.mu.RLock()
	_, ok := env.resolver.entries[vm100.ifname]
	env.resolver.mu.RUnlock()
	assert.True(t, ok, "pid Remove should not evict the cache entry")
}

// TestHandleEventChmodIgnored verifies that Chmod events (emitted by Linux
// inotify before a Remove) are silently ignored.
func TestHandleEventChmodIgnored(t *testing.T) {
	fw, env := newFW(t)
	env.addVM(t, vm100)
	env.populate(t, vm100)

	fw.handleEvent(confEvent(vm100.vmid, fsnotify.Chmod))

	env.resolver.mu.RLock()
	_, ok := env.resolver.entries[vm100.ifname]
	env.resolver.mu.RUnlock()
	assert.True(t, ok, "Chmod event must not evict the cache entry")
}

// TestHandleEventUnknownFile verifies that events for files not matching
// the conf or pid patterns are silently ignored.
func TestHandleEventUnknownFile(t *testing.T) {
	fw, env := newFW(t)
	// Should not panic or error regardless of content.
	fw.handleEvent(fsnotify.Event{
		Name: "/etc/pve/qemu-server/some-other-file.json",
		Op:   fsnotify.Write,
	})
	assert.Empty(t, env.resolver.entries)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func testCtx() context.Context { return context.Background() }

func tapwatchCreatedEvent(f vmFixture) tapwatch.Event {
	return tapwatch.Event{Type: tapwatch.Created, Name: f.ifname, Index: f.ifindex}
}

// Ensure vmproc is referenced (it's used via newTestEnv → vmproc.New).
var _ = vmproc.New
