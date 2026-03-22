package identity

import (
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
// the conf pattern are silently ignored.
func TestHandleEventUnknownFile(t *testing.T) {
	fw, env := newFW(t)
	// Should not panic or error regardless of content.
	fw.handleEvent(fsnotify.Event{
		Name: "/etc/pve/qemu-server/some-other-file.json",
		Op:   fsnotify.Write,
	})
	assert.Empty(t, env.resolver.entries)
}
