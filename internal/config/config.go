// Package config defines the pve-imds configuration structure and defaults.
package config

// Config holds all pve-imds configuration.
type Config struct {
	// LogLevel is the minimum log level to emit (debug, info, warn, error).
	LogLevel string `mapstructure:"log_level"`
	// FxLogging enables fx lifecycle logging.
	FxLogging bool `mapstructure:"fx_logging"`
	// Emulate selects the IMDS emulation target (ec2, openstack).
	Emulate string `mapstructure:"emulate"`
	// PprofAddr is the address to serve pprof endpoints; disabled if empty.
	PprofAddr string `mapstructure:"pprof_addr"`
	// MetricsAddr is the address to serve Prometheus metrics; disabled if empty.
	MetricsAddr string `mapstructure:"metrics_addr"`
}

// Default returns a Config with sensible defaults.
func Default() Config {
	return Config{
		LogLevel: "info",
		Emulate:  "openstack",
	}
}
