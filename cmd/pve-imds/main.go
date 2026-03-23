// Command pve-imds is the main daemon for the Proxmox VE IMDS service.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"

	"github.com/wyattanderson/pve-imds/internal/config"
	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/iface"
	"github.com/wyattanderson/pve-imds/internal/imds"
	"github.com/wyattanderson/pve-imds/internal/imds/ec2"
	"github.com/wyattanderson/pve-imds/internal/logging"
	"github.com/wyattanderson/pve-imds/internal/manager"
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
	var pprofAddr string
	var emulate string

	root := &cobra.Command{
		Use:   "pve-imds",
		Short: "IMDS-compatible metadata service for Proxmox VE",
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			return initConfig(cfgFile)
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return runServe(fxLogging, pprofAddr, emulate)
		},
	}

	pf := root.PersistentFlags()
	pf.StringVar(&cfgFile, "config", "", "config file (default: /etc/pve-imds/config.yaml)")
	pf.BoolVar(&fxLogging, "fx-logging", false, "enable fx lifecycle logging")
	pf.String("log-level", "info", "log level (debug, info, warn, error)")
	pf.String("socket-path", "/run/pve-imds/meta.sock", "Unix socket path for metadata backend")
	pf.StringVar(&pprofAddr, "pprof-addr", "", "address to serve pprof endpoints (e.g. localhost:6060); disabled if unset")
	root.Flags().StringVar(&emulate, "emulate", "ec2", "IMDS emulation target (ec2)")

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

func runServe(fxLogging bool, pprofAddr string, emulate string) error {
	var cfg config.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return fmt.Errorf("unmarshal config: %w", err)
	}

	var imdsServer imds.Server
	switch emulate {
	case "ec2":
		imdsServer = ec2.NewServer()
	default:
		return fmt.Errorf("unsupported --emulate value %q (supported: ec2)", emulate)
	}

	logger := logging.New(cfg.LogLevel)

	fxLogger := fx.NopLogger
	if fxLogging {
		fxLogger = fx.WithLogger(func() fxevent.Logger { return &fxevent.SlogLogger{Logger: logger} })
	}

	var pprofOpt fx.Option
	if pprofAddr != "" {
		addr := pprofAddr
		pprofOpt = fx.Invoke(func(lc fx.Lifecycle) {
			mux := http.NewServeMux()
			mux.HandleFunc("/debug/pprof/", pprof.Index)
			mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
			mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
			mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
			mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
			srv := &http.Server{Addr: addr, Handler: mux}
			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					lc := &net.ListenConfig{}
					ln, err := lc.Listen(ctx, "tcp", addr)
					if err != nil {
						return fmt.Errorf("pprof listen %s: %w", addr, err)
					}
					go func() { _ = srv.Serve(ln) }()
					return nil
				},
				OnStop: func(ctx context.Context) error {
					return srv.Shutdown(ctx)
				},
			})
		})
	} else {
		pprofOpt = fx.Options()
	}

	app := fx.New(
		fx.Supply(cfg),
		fx.Supply(logger),
		fxLogger,
		fx.Provide(func() imds.Server { return imdsServer }),
		fx.Provide(tapwatch.NewNetlinkConn),
		fx.Provide(tapwatch.New),
		fx.Provide(iface.NewFactory),
		fx.Provide(manager.New),
		// Contribute manager to the event_sinks value group.
		fx.Provide(fx.Annotate(
			func(m *manager.Manager) tapwatch.EventSink { return m },
			fx.ResultTags(`group:"event_sinks"`),
		)),
		fx.Invoke(manager.Register),
		identity.Module,
		fx.Invoke(tapwatch.Register),
		pprofOpt,
	)

	startCtx, startCancel := context.WithTimeout(context.Background(), app.StartTimeout())
	defer startCancel()
	if err := app.Start(startCtx); err != nil {
		return err
	}

	sdNotifyReady()

	<-app.Done()

	stopCtx, stopCancel := context.WithTimeout(context.Background(), app.StopTimeout())
	defer stopCancel()
	return app.Stop(stopCtx)
}

// sdNotifyReady sends READY=1 to the systemd notification socket, if present.
// This implements the sd_notify(3) protocol for Type=notify services.
func sdNotifyReady() {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return
	}
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "unixgram", socket)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte("READY=1"))
}
