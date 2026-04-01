// Package config defines the pve-imds configuration structure and defaults.
package config

import (
	"os"
	"time"
)

// JWTSVIDConfig holds configuration for JWT-SVID issuance and JWKS serving.
type JWTSVIDConfig struct {
	// PrivateKeyPath is the path to the node's PEM-encoded RSA private key.
	// When using systemd credentials, set this to
	// /run/credentials/pve-imds.service/pve-ssl.key.
	PrivateKeyPath string `mapstructure:"private_key_path"`
	// TokenTTL is the lifetime of issued JWT-SVIDs. Default: 5 minutes.
	TokenTTL time.Duration `mapstructure:"token_ttl"`
	// NodesDir is the directory containing per-node PVE SSL certificates used
	// to build the JWKS response. Each subdirectory must contain pve-ssl.pem.
	NodesDir string `mapstructure:"nodes_dir"`
	// TrustDomain is the SPIFFE trust domain used in the sub claim, e.g.
	// "pve.example.com". Defaults to the node's hostname.
	TrustDomain string `mapstructure:"trust_domain"`
}

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
	// JWTSVID holds configuration for JWT-SVID issuance and JWKS serving.
	JWTSVID JWTSVIDConfig `mapstructure:"jwtsvid"`
}

// Default returns a Config with sensible defaults.
func Default() Config {
	hostname, _ := os.Hostname()
	return Config{
		LogLevel: "info",
		Emulate:  "openstack",
		JWTSVID: JWTSVIDConfig{
			PrivateKeyPath: "/etc/pve/local/pve-ssl.key",
			TokenTTL:       5 * time.Minute,
			NodesDir:       "/etc/pve/nodes",
			TrustDomain:    hostname,
		},
	}
}
