package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/mdlayher/netlink"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"

	"github.com/wyattanderson/pve-imds/internal/config"
	"github.com/wyattanderson/pve-imds/internal/logging"
	"github.com/wyattanderson/pve-imds/internal/tapwatch"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var cfgFile string
	var fxLogging bool

	root := &cobra.Command{
		Use:   "pve-imds",
		Short: "AWS IMDS-compatible metadata service for Proxmox VE",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initConfig(cfgFile)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(fxLogging)
		},
	}

	pf := root.PersistentFlags()
	pf.StringVar(&cfgFile, "config", "", "config file (default: /etc/pve-imds/config.yaml)")
	pf.BoolVar(&fxLogging, "fx-logging", false, "enable fx lifecycle logging")
	pf.String("log-level", "info", "log level (debug, info, warn, error)")
	pf.String("socket-path", "/run/pve-imds/meta.sock", "Unix socket path for metadata backend")

	if err := viper.BindPFlag("log_level", pf.Lookup("log-level")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("socket_path", pf.Lookup("socket-path")); err != nil {
		panic(err)
	}

	return root
}

func initConfig(cfgFile string) error {
	viper.SetEnvPrefix("PVE_IMDS")
	viper.AutomaticEnv()

	// Set defaults from our config struct.
	def := config.Default()
	viper.SetDefault("log_level", def.LogLevel)
	viper.SetDefault("socket_path", def.SocketPath)

	if cfgFile == "" {
		return nil
	}

	viper.SetConfigFile(cfgFile)
	return viper.ReadInConfig()
}

func runServe(fxLogging bool) error {
	var cfg config.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return fmt.Errorf("unmarshal config: %w", err)
	}

	logger := logging.New(cfg.LogLevel)

	fxLogger := fx.NopLogger
	if fxLogging {
		fxLogger = fx.WithLogger(func() fxevent.Logger { return &fxevent.SlogLogger{Logger: logger} })
	}

	app := fx.New(
		fx.Supply(cfg),
		fx.Supply(logger),
		fxLogger,
		fx.Provide(newNetlinkConn),
		fx.Provide(tapwatch.New),
		fx.Provide(newLoggingSink),
		fx.Invoke(registerWatcher),
	)

	app.Run()
	return nil
}

// newNetlinkConn opens a NETLINK_ROUTE socket subscribed to RTNLGRP_LINK.
func newNetlinkConn() (*netlink.Conn, error) {
	conn, err := netlink.Dial(0, nil) // 0 = NETLINK_ROUTE
	if err != nil {
		return nil, fmt.Errorf("dial netlink: %w", err)
	}
	if err := conn.JoinGroup(1); err != nil { // 1 = RTNLGRP_LINK
		conn.Close()
		return nil, fmt.Errorf("join RTNLGRP_LINK: %w", err)
	}
	return conn, nil
}

// loggingEventSink logs tap interface lifecycle events via slog.
type loggingEventSink struct {
	log *slog.Logger
}

func newLoggingSink(log *slog.Logger) tapwatch.EventSink {
	return &loggingEventSink{log: log}
}

func (s *loggingEventSink) HandleLinkEvent(ctx context.Context, ev tapwatch.Event) {
	typ := "created"
	if ev.Type == tapwatch.Deleted {
		typ = "deleted"
	}
	s.log.InfoContext(ctx, "tap interface event", "event", typ, "name", ev.Name, "index", ev.Index)
}

// registerWatcher wires the Watcher into the fx lifecycle: Run starts on
// OnStart and is stopped by cancelling its context on OnStop.
func registerWatcher(lc fx.Lifecycle, w *tapwatch.Watcher, sink tapwatch.EventSink, log *slog.Logger) {
	ctx, cancel := context.WithCancel(context.Background())
	lc.Append(fx.Hook{
		OnStart: func(_ context.Context) error {
			log.Info("starting tap interface watcher")
			go func() {
				if err := w.Run(ctx, sink); err != nil {
					log.Error("tap watcher exited", "err", err)
				}
			}()
			return nil
		},
		OnStop: func(_ context.Context) error {
			log.Info("stopping tap interface watcher")
			cancel()
			return nil
		},
	})
}
