package identity

import (
	"context"
	"log/slog"

	"github.com/spf13/afero"
	"go.uber.org/fx"

	"github.com/wyattanderson/pve-imds/internal/tapwatch"
	"github.com/wyattanderson/pve-imds/internal/vmproc"
)

// Module bundles the full identity subsystem as an fx.Option. Include it in
// the root fx.New call to wire the resolver, file watcher, and event sink.
var Module = fx.Module("identity",
	// Real OS filesystem shared by both the config reader and the proc tracker.
	fx.Provide(func() afero.Fs { return afero.NewOsFs() }),

	// Process tracker (reads /var/run/qemu-server/*.pid and /proc/*/stat).
	fx.Provide(vmproc.New),

	// Resolver: provides *Resolver for internal wiring and Provider for the
	// HTTP proxy layer.
	fx.Provide(New),
	fx.Provide(func(r *Resolver) Provider { return r }),

	// Promote Resolver into the "event_sinks" value group so tapwatch.Register
	// picks it up alongside any other registered sinks.
	fx.Provide(fx.Annotate(
		func(r *Resolver) tapwatch.EventSink { return r },
		fx.ResultTags(`group:"event_sinks"`),
	)),

	// File watcher for /etc/pve/qemu-server/ and /var/run/qemu-server/.
	fx.Provide(NewFileWatcher),
	fx.Invoke(RegisterLifecycle),
)

// RegisterLifecycle is an fx.Invoke target that starts FileWatcher.Run in the
// background and stops it cleanly on application shutdown.
func RegisterLifecycle(lc fx.Lifecycle, fw *FileWatcher, log *slog.Logger) {
	ctx, cancel := context.WithCancel(context.Background())
	lc.Append(fx.Hook{
		OnStart: func(_ context.Context) error {
			log.Info("starting identity file watcher")
			go func() {
				if err := fw.Run(ctx); err != nil {
					log.Error("identity file watcher exited", "err", err)
				}
			}()
			return nil
		},
		OnStop: func(_ context.Context) error {
			log.Info("stopping identity file watcher")
			cancel()
			return nil
		},
	})
}
