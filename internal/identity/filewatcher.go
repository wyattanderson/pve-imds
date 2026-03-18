package identity

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/fsnotify/fsnotify"
)

const (
	defaultConfDir = "/etc/pve/qemu-server"
	defaultPIDDir  = "/var/run/qemu-server"
)

var (
	confFileRe = regexp.MustCompile(`^(\d+)\.conf$`)
	pidFileRe  = regexp.MustCompile(`^(\d+)\.pid$`)
)

// resolverSink is the subset of *Resolver that FileWatcher calls back into.
// The interface exists so that integration tests can inject a spy without
// needing the real resolver's hardcoded file paths.
type resolverSink interface {
	ReloadConfig(vmid int)
	ReloadProcess(vmid int)
	invalidateByVMID(vmid int)
}

// FileWatcher watches the Proxmox config and PID directories for changes and
// keeps the identity cache consistent by calling the appropriate resolver
// methods when files are created, written, or deleted.
type FileWatcher struct {
	resolver resolverSink
	watcher  *fsnotify.Watcher
	log      *slog.Logger
}

// NewFileWatcher creates a FileWatcher that watches the production Proxmox
// directories and calls back into resolver on relevant changes.
func NewFileWatcher(resolver *Resolver, log *slog.Logger) (*FileWatcher, error) {
	return newFileWatcherWithDirs(resolver, log, defaultConfDir, defaultPIDDir)
}

// newFileWatcherWithDirs is the real constructor, accepting explicit directory
// paths. Used by NewFileWatcher (production) and integration tests (temp dirs).
func newFileWatcherWithDirs(resolver resolverSink, log *slog.Logger, confDir, pidDir string) (*FileWatcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("identity: create fsnotify watcher: %w", err)
	}
	for _, dir := range []string{confDir, pidDir} {
		if err := w.Add(dir); err != nil {
			w.Close()
			return nil, fmt.Errorf("identity: watch %s: %w", dir, err)
		}
	}
	return &FileWatcher{resolver: resolver, watcher: w, log: log}, nil
}

// Run processes filesystem events until ctx is cancelled. It should be started
// in a goroutine. Run always returns nil on a clean shutdown (ctx cancelled or
// watcher channels closed).
func (fw *FileWatcher) Run(ctx context.Context) error {
	defer fw.watcher.Close()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return nil
			}
			fw.log.Warn("identity: filewatcher error", "err", err)
		case ev, ok := <-fw.watcher.Events:
			if !ok {
				return nil
			}
			fw.handleEvent(ev)
		}
	}
}

// handleEvent dispatches a single fsnotify event to the appropriate resolver
// method. Unknown filenames and irrelevant ops (e.g. Chmod on Linux during
// deletion) are silently ignored.
func (fw *FileWatcher) handleEvent(ev fsnotify.Event) {
	base := filepath.Base(ev.Name)

	if m := confFileRe.FindStringSubmatch(base); m != nil {
		vmid, _ := strconv.Atoi(m[1])
		switch {
		case ev.Has(fsnotify.Write) || ev.Has(fsnotify.Create):
			fw.log.Debug("identity: conf written, reloading config", "vmid", vmid, "path", ev.Name)
			fw.resolver.ReloadConfig(vmid)
		case ev.Has(fsnotify.Remove) || ev.Has(fsnotify.Rename):
			fw.log.Debug("identity: conf removed, invalidating entries", "vmid", vmid, "path", ev.Name)
			fw.resolver.invalidateByVMID(vmid)
		}
		return
	}

	if m := pidFileRe.FindStringSubmatch(base); m != nil {
		vmid, _ := strconv.Atoi(m[1])
		if ev.Has(fsnotify.Write) || ev.Has(fsnotify.Create) {
			fw.log.Debug("identity: pid written, reloading process info", "vmid", vmid, "path", ev.Name)
			fw.resolver.ReloadProcess(vmid)
		}
	}
}
