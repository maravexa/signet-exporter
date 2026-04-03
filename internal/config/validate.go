package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
)

// Validate checks the configuration for logical errors and missing required fields.
func Validate(cfg *Config) error {
	if err := validateListenAddress(cfg.ListenAddress); err != nil {
		return fmt.Errorf("listen_address: %w", err)
	}

	if err := validateTLS(&cfg.TLS); err != nil {
		return fmt.Errorf("tls: %w", err)
	}

	if len(cfg.Subnets) == 0 {
		return fmt.Errorf("subnets: at least one subnet must be configured")
	}

	for i, s := range cfg.Subnets {
		if err := validateSubnet(&s); err != nil {
			return fmt.Errorf("subnets[%d]: %w", i, err)
		}
	}

	if cfg.Scanner.MaxParallelScans < 1 {
		return fmt.Errorf("scanner.max_parallel_scans: must be >= 1")
	}

	if cfg.State.Backend != "memory" && cfg.State.Backend != "bolt" {
		return fmt.Errorf("state.backend: must be \"memory\" or \"bolt\"")
	}

	if cfg.State.Backend == "bolt" && cfg.State.BoltPath == "" {
		return fmt.Errorf("state.bolt_path: required when backend is \"bolt\"")
	}

	if err := validateAudit(&cfg.Audit); err != nil {
		return fmt.Errorf("audit: %w", err)
	}

	return nil
}

func validateAudit(a *AuditConfig) error {
	if !a.Enabled || a.Output == "" || a.Output == "stderr" {
		return nil
	}
	// File output: verify the parent directory exists.
	dir := filepath.Dir(a.Output)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("output: parent directory %q does not exist", dir)
	}
	return nil
}

func validateListenAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("port must be specified")
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return fmt.Errorf("binding to all interfaces (%q) is not permitted; use a specific address", host)
	}
	return nil
}

func validateTLS(tls *TLSConfig) error {
	if tls.MinVersion != "" && tls.MinVersion != "1.2" && tls.MinVersion != "1.3" {
		return fmt.Errorf("min_version must be \"1.2\" or \"1.3\"")
	}
	// Both cert and key must be provided together, or neither (plaintext mode).
	if (tls.CertFile == "") != (tls.KeyFile == "") {
		return fmt.Errorf("cert_file and key_file must both be set or both be empty")
	}
	// mTLS requires a server cert.
	if tls.ClientCAFile != "" && tls.CertFile == "" {
		return fmt.Errorf("client_ca_file requires cert_file and key_file to be set")
	}
	switch tls.ClientAuthPolicy {
	case "", "require_and_verify", "verify_if_given", "no_client_cert":
		// valid
	default:
		return fmt.Errorf("client_auth_policy must be \"require_and_verify\", \"verify_if_given\", or \"no_client_cert\"")
	}
	return nil
}

func validateSubnet(s *SubnetConfig) error {
	if s.CIDR == "" {
		return fmt.Errorf("cidr is required")
	}
	if _, err := netip.ParsePrefix(s.CIDR); err != nil {
		return fmt.Errorf("cidr %q is not a valid CIDR prefix: %w", s.CIDR, err)
	}
	if s.ScanInterval <= 0 {
		return fmt.Errorf("scan_interval must be > 0")
	}
	if s.MACAllowlistFile != "" {
		if _, err := os.Stat(s.MACAllowlistFile); os.IsNotExist(err) {
			return fmt.Errorf("mac_allowlist_file %q does not exist", s.MACAllowlistFile)
		}
	}
	return nil
}
