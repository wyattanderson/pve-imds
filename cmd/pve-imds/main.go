// Command pve-imds is the main daemon for the Proxmox VE IMDS service.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"

	"github.com/wyattanderson/pve-imds/internal/config"
	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/iface"
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

	root := &cobra.Command{
		Use:   "pve-imds",
		Short: "AWS IMDS-compatible metadata service for Proxmox VE",
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			return initConfig(cfgFile)
		},
		RunE: func(_ *cobra.Command, _ []string) error {
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
	)

	app.Run()
	return nil
}
