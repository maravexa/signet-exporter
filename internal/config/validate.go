package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
)

// minIPv4DiscoveryPrefixBits bounds per-cycle probe work to 65,534 usable
// addresses. Larger networks must be declared as non-overlapping subnets.
const minIPv4DiscoveryPrefixBits = 16

// Validate checks the configuration for logical errors and missing required fields.
func Validate(cfg *Config) error {
	if err := validateListenAddress(cfg.ListenAddress); err != nil {
		return fmt.Errorf("listen_address: %w", err)
	}

	if err := validateTLS(&cfg.TLS); err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	if err := validateDNS(&cfg.DNS); err != nil {
		return fmt.Errorf("dns: %w", err)
	}

	if len(cfg.Subnets) == 0 {
		return fmt.Errorf("subnets: at least one subnet must be configured")
	}

	prefixes := make([]netip.Prefix, 0, len(cfg.Subnets))
	for i, s := range cfg.Subnets {
		if err := validateSubnet(&s); err != nil {
			return fmt.Errorf("subnets[%d]: %w", i, err)
		}
		prefix := netip.MustParsePrefix(s.CIDR).Masked()
		for _, existing := range prefixes {
			if prefixesOverlap(existing, prefix) {
				return fmt.Errorf("subnets[%d]: cidr %q overlaps configured subnet %q", i, s.CIDR, existing)
			}
		}
		prefixes = append(prefixes, prefix)
	}
	if cfg.HostTTL < 0 {
		return fmt.Errorf("host_ttl: must be >= 0")
	}

	if cfg.Scanner.MaxParallelScans < 1 {
		return fmt.Errorf("scanner.max_parallel_scans: must be >= 1")
	}
	if cfg.Scanner.ICMPTimeout <= 0 || cfg.Scanner.ARPTimeout <= 0 || cfg.Scanner.PortTimeout <= 0 {
		return fmt.Errorf("scanner: icmp_timeout, arp_timeout, and port_timeout must be > 0")
	}
	if cfg.Scanner.ICMPRateLimit < 0 || cfg.Scanner.ARPRateLimit < 0 {
		return fmt.Errorf("scanner: rate limits must be >= 0")
	}
	if cfg.Scanner.PortMaxWorkers < 1 {
		return fmt.Errorf("scanner.port_max_workers: must be >= 1")
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

	if err := cfg.RemoteWrite.Validate(); err != nil {
		// Both fatal errors and *ConfigWarning are wrapped; callers that wish
		// to downgrade warnings can inspect via remotewrite.IsWarning(err).
		return fmt.Errorf("remote_write: %w", err)
	}

	return nil
}

func validateDNS(dns *DNSConfig) error {
	if dns.Timeout <= 0 {
		return fmt.Errorf("timeout must be > 0")
	}
	for i, server := range dns.Servers {
		host, port, err := net.SplitHostPort(server)
		if err != nil || host == "" || port == "" {
			return fmt.Errorf("servers[%d]: %q must be a host:port address", i, server)
		}
		portNumber, err := strconv.ParseUint(port, 10, 16)
		if err != nil || portNumber == 0 {
			return fmt.Errorf("servers[%d]: port must be a number from 1 to 65535", i)
		}
	}
	return nil
}

func validateAudit(a *AuditConfig) error {
	switch a.Format {
	case "", "json", "cef":
		// valid
	default:
		return fmt.Errorf("format must be \"json\" or \"cef\"")
	}

	if !a.Enabled {
		return nil
	}

	switch a.Output {
	case "", "stderr", "stdout":
		return nil
	case "file":
		path := a.Path
		if path == "" {
			path = "/var/log/signet/audit.log"
		}
		if err := validateAuditPath(path, "path"); err != nil {
			return err
		}
	default:
		// Backward compat: Output treated as a file path.
		if err := validateAuditPath(a.Output, "output"); err != nil {
			return err
		}
	}
	return nil
}

func validateAuditPath(path, field string) error {
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("%s: parent directory %q: %w", field, dir, err)
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil // NewLogger creates the file with 0640.
	}
	if err != nil {
		return fmt.Errorf("%s: lstat %q: %w", field, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: existing audit target %q must not be a symlink", field, path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s: existing audit target %q must be a regular file", field, path)
	}
	if info.Mode().Perm()&0o007 != 0 {
		return fmt.Errorf("%s: existing audit target %q must not be accessible by other users", field, path)
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
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return fmt.Errorf("port must be a number from 1 to 65535, got %q", port)
	}
	if host == "" {
		return fmt.Errorf("binding to all interfaces (%q) is not permitted; use a specific address", host)
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Unmap().IsUnspecified() {
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
	if tls.CertFile != "" {
		if err := validateRegularFile(tls.CertFile, "cert_file", false); err != nil {
			return err
		}
		if err := validateRegularFile(tls.KeyFile, "key_file", true); err != nil {
			return err
		}
	}
	if tls.ClientCAFile != "" {
		if err := validateRegularFile(tls.ClientCAFile, "client_ca_file", false); err != nil {
			return err
		}
	}
	switch tls.ClientAuthPolicy {
	case "", "require_and_verify", "verify_if_given", "no_client_cert":
		// valid
	default:
		return fmt.Errorf("client_auth_policy must be \"require_and_verify\", \"verify_if_given\", or \"no_client_cert\"")
	}
	if tls.ClientCAFile == "" && (tls.ClientAuthPolicy == "require_and_verify" || tls.ClientAuthPolicy == "verify_if_given") {
		return fmt.Errorf("client_auth_policy %q requires client_ca_file; otherwise client certificate verification cannot be performed", tls.ClientAuthPolicy)
	}
	if tls.ClientCAFile != "" && tls.ClientAuthPolicy == "no_client_cert" {
		return fmt.Errorf("client_auth_policy \"no_client_cert\" cannot be used with client_ca_file")
	}
	return nil
}

// validateRegularFile rejects device/FIFO/directory inputs before a privileged
// transport path opens them. Private files may be group-readable for the
// signet service group, but never accessible by "other" users.
func validateRegularFile(path, field string, private bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s %q must not be a symlink", field, path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s %q must be a regular file", field, path)
	}
	if private && info.Mode().Perm()&0o007 != 0 {
		return fmt.Errorf("%s %q must not be accessible by other users", field, path)
	}
	return nil
}

func validateSubnet(s *SubnetConfig) error {
	if s.CIDR == "" {
		return fmt.Errorf("cidr is required")
	}
	prefix, err := netip.ParsePrefix(s.CIDR)
	if err != nil {
		return fmt.Errorf("cidr %q is not a valid CIDR prefix: %w", s.CIDR, err)
	}
	if !prefix.Addr().Is4() {
		return fmt.Errorf("cidr %q: IPv6 discovery is not supported", s.CIDR)
	}
	if prefix.Bits() < minIPv4DiscoveryPrefixBits {
		return fmt.Errorf("cidr %q is too large for discovery (minimum prefix is /%d)", s.CIDR, minIPv4DiscoveryPrefixBits)
	}
	if s.ScanInterval <= 0 {
		return fmt.Errorf("scan_interval must be > 0")
	}
	seenPorts := make(map[uint16]bool, len(s.Ports))
	for _, port := range s.Ports {
		if port == 0 {
			return fmt.Errorf("port must be in range 1–65535")
		}
		if seenPorts[port] {
			return fmt.Errorf("duplicate port %d", port)
		}
		seenPorts[port] = true
	}
	if s.MACAllowlistFile != "" {
		if _, err := os.Stat(s.MACAllowlistFile); os.IsNotExist(err) {
			return fmt.Errorf("mac_allowlist_file %q does not exist", s.MACAllowlistFile)
		}
	}
	return nil
}
