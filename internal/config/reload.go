package config

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"time"
)

// ReloadableSubnet holds the mutable per-subnet configuration that can be updated
// at runtime via SIGHUP without restarting the exporter.
type ReloadableSubnet struct {
	CIDR             string
	ScanInterval     time.Duration
	Ports            []int  // 1–65535; validated by ValidateReloadable
	MACAllowlistFile string // empty = no authorization checking
}

// ReloadableConfig is the subset of Config that can be updated at runtime via SIGHUP.
//
// Immutable settings — require a restart to take effect:
//   - listen_address (socket rebind required)
//   - tls.* (cert paths, min_version — cert contents rotate via SIGHUP separately)
//   - state.* (backend switch requires store migration)
type ReloadableConfig struct {
	Subnets []ReloadableSubnet
	HostTTL time.Duration
	// HostTTLSet preserves the distinction between an omitted host_ttl and an
	// explicit host_ttl: 0 during a live reload.
	HostTTLSet bool
}

// ExtractReloadable extracts the mutable portion from a full Config.
func ExtractReloadable(cfg *Config) ReloadableConfig {
	subnets := make([]ReloadableSubnet, len(cfg.Subnets))
	for i, s := range cfg.Subnets {
		ports := make([]int, len(s.Ports))
		for j, p := range s.Ports {
			ports[j] = int(p)
		}
		subnets[i] = ReloadableSubnet{
			CIDR:             s.CIDR,
			ScanInterval:     s.ScanInterval,
			Ports:            ports,
			MACAllowlistFile: s.MACAllowlistFile,
		}
	}
	return ReloadableConfig{Subnets: subnets, HostTTL: cfg.HostTTL, HostTTLSet: cfg.HostTTLSet}
}

// ValidateReloadable checks the mutable config subset for logical errors.
//
// Validation runs BEFORE applying the new config. If validation fails the old
// config stays active — partial application is never possible.
func ValidateReloadable(rc ReloadableConfig) error {
	seen := make(map[netip.Prefix]bool, len(rc.Subnets))
	prefixes := make([]netip.Prefix, 0, len(rc.Subnets))
	for _, s := range rc.Subnets {
		prefix, err := netip.ParsePrefix(s.CIDR)
		if err != nil {
			return fmt.Errorf("subnet %q: invalid CIDR: %w", s.CIDR, err)
		}
		prefix = prefix.Masked()
		if !prefix.Addr().Is4() {
			return fmt.Errorf("subnet %q: IPv6 discovery is not supported", s.CIDR)
		}
		if prefix.Bits() < minIPv4DiscoveryPrefixBits {
			return fmt.Errorf("subnet %q is too large for discovery (minimum prefix is /%d)", s.CIDR, minIPv4DiscoveryPrefixBits)
		}
		if seen[prefix] {
			return fmt.Errorf("subnet %q: duplicate CIDR", s.CIDR)
		}
		for _, existing := range prefixes {
			if prefixesOverlap(existing, prefix) {
				return fmt.Errorf("subnet %q: overlaps configured subnet %q", s.CIDR, existing)
			}
		}
		seen[prefix] = true
		prefixes = append(prefixes, prefix)
		if s.ScanInterval <= 0 {
			return fmt.Errorf("subnet %q: scan_interval must be > 0", s.CIDR)
		}
		seenPorts := make(map[int]bool, len(s.Ports))
		for _, port := range s.Ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("subnet %q: port %d out of range (1–65535)", s.CIDR, port)
			}
			if seenPorts[port] {
				return fmt.Errorf("subnet %q: duplicate port %d", s.CIDR, port)
			}
			seenPorts[port] = true
		}
		if s.MACAllowlistFile != "" {
			if _, err := os.Stat(s.MACAllowlistFile); err != nil {
				return fmt.Errorf("subnet %q: allowlist file %q: %w", s.CIDR, s.MACAllowlistFile, err)
			}
		}
	}
	if rc.HostTTL < 0 {
		return fmt.Errorf("host_ttl must be >= 0")
	}
	return nil
}

func prefixesOverlap(a, b netip.Prefix) bool {
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
}

// Diff compares two ReloadableConfigs and returns a human-readable list of changes.
// Returns an empty slice when the configs are identical.
// Output is sorted for deterministic audit log entries.
func Diff(old, new ReloadableConfig) []string {
	var changes []string

	oldByCI := make(map[string]ReloadableSubnet, len(old.Subnets))
	for _, s := range old.Subnets {
		oldByCI[s.CIDR] = s
	}
	newByCI := make(map[string]ReloadableSubnet, len(new.Subnets))
	for _, s := range new.Subnets {
		newByCI[s.CIDR] = s
	}

	for cidr := range newByCI {
		if _, exists := oldByCI[cidr]; !exists {
			changes = append(changes, fmt.Sprintf("subnet %s: added", cidr))
		}
	}
	for cidr := range oldByCI {
		if _, exists := newByCI[cidr]; !exists {
			changes = append(changes, fmt.Sprintf("subnet %s: removed", cidr))
		}
	}
	for cidr, ns := range newByCI {
		os, exists := oldByCI[cidr]
		if !exists {
			continue // already recorded as added
		}
		if os.ScanInterval != ns.ScanInterval {
			changes = append(changes, fmt.Sprintf("subnet %s: scan_interval %s → %s", cidr, os.ScanInterval, ns.ScanInterval))
		}
		if !intsEqual(os.Ports, ns.Ports) {
			changes = append(changes, fmt.Sprintf("subnet %s: ports changed", cidr))
		}
		if os.MACAllowlistFile != ns.MACAllowlistFile {
			changes = append(changes, fmt.Sprintf("subnet %s: allowlist %s → %s", cidr, os.MACAllowlistFile, ns.MACAllowlistFile))
		}
	}

	if old.HostTTL != new.HostTTL || old.HostTTLSet != new.HostTTLSet {
		changes = append(changes, fmt.Sprintf("host_ttl: %s → %s", formatHostTTL(old), formatHostTTL(new)))
	}

	sort.Strings(changes)
	return changes
}

func formatHostTTL(rc ReloadableConfig) string {
	if !rc.HostTTLSet {
		return "default"
	}
	return rc.HostTTL.String()
}

func intsEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
