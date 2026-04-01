// Command pve-imds is the main daemon for the Proxmox VE IMDS service.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime/debug"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"

	"github.com/wyattanderson/pve-imds/internal/config"
	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/iface"
	"github.com/wyattanderson/pve-imds/internal/imds"
	"github.com/wyattanderson/pve-imds/internal/imds/ec2"
	"github.com/wyattanderson/pve-imds/internal/imds/jwtsvid"
	"github.com/wyattanderson/pve-imds/internal/imds/openstack"
	"github.com/wyattanderson/pve-imds/internal/logging"
	"github.com/wyattanderson/pve-imds/internal/manager"
	"github.com/wyattanderson/pve-imds/internal/tapwatch"
)

// version is set at build time via -ldflags "-X main.version=<ver>".
var version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var cfgFile string

	root := &cobra.Command{
		Use:   "pve-imds",
		Short: "IMDS-compatible metadata service for Proxmox VE",
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			return initConfig(cfgFile)
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return runServe()
		},
	}

	pf := root.PersistentFlags()
	pf.StringVar(&cfgFile, "config", "", "config file (default: /etc/pve-imds/config.yaml)")
	pf.Bool("fx_logging", false, "enable fx lifecycle logging")
	pf.String("log_level", "info", "log level (debug, info, warn, error)")
	pf.String("pprof_addr", "", "address to serve pprof endpoints (e.g. localhost:6060); disabled if unset")
	pf.String("metrics_addr", "", "address to serve Prometheus metrics (e.g. :9100); disabled if unset")
	pf.String("emulate", "ec2", "IMDS emulation target (ec2, openstack)")

	if err := viper.BindPFlags(pf); err != nil {
		panic(err)
	}

	return root
}

func initConfig(cfgFile string) error {
	viper.SetEnvPrefix("PVE_IMDS")
	viper.AutomaticEnv()

	def := config.Default()
	viper.SetDefault("log_level", def.LogLevel)
	viper.SetDefault("emulate", def.Emulate)
	viper.SetDefault("jwtsvid.private_key_path", def.JWTSVID.PrivateKeyPath)
	viper.SetDefault("jwtsvid.token_ttl", def.JWTSVID.TokenTTL)
	viper.SetDefault("jwtsvid.nodes_dir", def.JWTSVID.NodesDir)
	viper.SetDefault("jwtsvid.trust_domain", def.JWTSVID.TrustDomain)

	if cfgFile == "" {
		return nil
	}

	viper.SetConfigFile(cfgFile)
	return viper.ReadInConfig()
}

func runServe() error {
	var cfg config.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return fmt.Errorf("unmarshal config: %w", err)
	}

	var imdsServer imds.Server
	switch cfg.Emulate {
	case "ec2":
		imdsServer = ec2.NewServer()
	case "openstack":
		imdsServer = openstack.NewServer()
	default:
		return fmt.Errorf("unsupported --emulate value %q (supported: ec2, openstack)", cfg.Emulate)
	}

	logger := logging.New(cfg.LogLevel)

	if info, ok := debug.ReadBuildInfo(); ok {
		var revision, buildTime string
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.time":
				buildTime = s.Value
			}
		}
		logger.Info("starting pve-imds",
			"version", version,
			"go", info.GoVersion,
			"revision", revision,
			"built", buildTime,
		)
	}

	fxLogger := fx.NopLogger
	if cfg.FxLogging {
		fxLogger = fx.WithLogger(func() fxevent.Logger { return &fxevent.SlogLogger{Logger: logger} })
	}

	var opts []fx.Option
	if cfg.PprofAddr != "" {
		opts = append(opts, pprofOption(cfg.PprofAddr))
	}
	if cfg.MetricsAddr != "" {
		opts = append(opts, metricsOption(cfg.MetricsAddr))
	}

	app := fx.New(
		fx.Supply(cfg),
		fx.Supply(logger),
		fxLogger,
		fx.Provide(func() imds.Server { return imdsServer }),
		fx.Provide(func(cfg config.Config) (*jwtsvid.Signer, error) {
			return jwtsvid.NewSigner(cfg.JWTSVID)
		}),
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
		fx.Options(opts...),
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
