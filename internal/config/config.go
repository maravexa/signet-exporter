// Package config defines the configuration structure and loader for signet-exporter.
package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration structure for signet-exporter.
type Config struct {
	ListenAddress string         `yaml:"listen_address"`
	TLS           TLSConfig      `yaml:"tls"`
	Subnets       []SubnetConfig `yaml:"subnets"`
	DNS           DNSConfig      `yaml:"dns"`
	Scanner       ScannerConfig  `yaml:"scanner"`
	State         StateConfig    `yaml:"state"`
	OUIDatabase   string         `yaml:"oui_database"`
	Audit         AuditConfig    `yaml:"audit"`
}

// TLSConfig holds TLS and mTLS settings for the metrics endpoint.
type TLSConfig struct {
	CertFile         string `yaml:"cert_file"`
	KeyFile          string `yaml:"key_file"`
	ClientCAFile     string `yaml:"client_ca_file"`
	ClientAuthPolicy string `yaml:"client_auth_policy"` // "require_and_verify" | "verify_if_given" | "no_client_cert"
	MinVersion       string `yaml:"min_version"`
}

// SubnetConfig describes a single subnet to scan.
type SubnetConfig struct {
	CIDR             string        `yaml:"cidr"`
	ScanInterval     time.Duration `yaml:"scan_interval"`
	Ports            []uint16      `yaml:"ports"`
	MACAllowlistFile string        `yaml:"mac_allowlist_file"`
}

// DNSConfig holds settings for DNS resolution probes.
type DNSConfig struct {
	Servers []string      `yaml:"servers"`
	Timeout time.Duration `yaml:"timeout"`
}

// ScannerConfig holds global scanner concurrency and timeout settings.
type ScannerConfig struct {
	MaxParallelScans int           `yaml:"max_parallel_scans"`
	ICMPTimeout      time.Duration `yaml:"icmp_timeout"`
	ICMPRateLimit    time.Duration `yaml:"icmp_rate_limit"`
	ARPTimeout       time.Duration `yaml:"arp_timeout"`
	ARPRateLimit     time.Duration `yaml:"arp_rate_limit"`
	PortTimeout      time.Duration `yaml:"port_timeout"`
	PortMaxWorkers   int           `yaml:"port_max_workers"`
}

// StateConfig holds configuration for the state persistence backend.
type StateConfig struct {
	Backend  string `yaml:"backend"` // "memory" or "bolt"
	BoltPath string `yaml:"bolt_path"`
}

// AuditConfig holds structured audit log settings.
type AuditConfig struct {
	Enabled bool   `yaml:"enabled"`
	Output  string `yaml:"output"` // "stderr" or file path
}

// DefaultConfig returns a safe default configuration.
// The listen address defaults to loopback — never 0.0.0.0.
func DefaultConfig() *Config {
	return &Config{
		ListenAddress: "127.0.0.1:9420",
		TLS: TLSConfig{
			MinVersion: "1.3",
		},
		DNS: DNSConfig{
			Timeout: 2 * time.Second,
		},
		Scanner: ScannerConfig{
			MaxParallelScans: 4,
			ICMPTimeout:      1 * time.Second,
			ICMPRateLimit:    200 * time.Microsecond,
			ARPTimeout:       2 * time.Second,
			ARPRateLimit:     500 * time.Microsecond,
			PortTimeout:      1 * time.Second,
			PortMaxWorkers:   32,
		},
		State: StateConfig{
			Backend:  "memory",
			BoltPath: "/var/lib/signet/state.db",
		},
		OUIDatabase: "/usr/share/signet/oui.txt",
		Audit: AuditConfig{
			Enabled: true,
			Output:  "stderr",
		},
	}
}

// LoadConfig reads and parses a YAML configuration file at path.
// It starts from DefaultConfig and overlays the file values.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
