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
	return ReloadableConfig{Subnets: subnets}
}

// ValidateReloadable checks the mutable config subset for logical errors.
//
// Validation runs BEFORE applying the new config. If validation fails the old
// config stays active — partial application is never possible.
func ValidateReloadable(rc ReloadableConfig) error {
	seen := make(map[string]bool, len(rc.Subnets))
	for _, s := range rc.Subnets {
		if _, err := netip.ParsePrefix(s.CIDR); err != nil {
			return fmt.Errorf("subnet %q: invalid CIDR: %w", s.CIDR, err)
		}
		if seen[s.CIDR] {
			return fmt.Errorf("subnet %q: duplicate CIDR", s.CIDR)
		}
		seen[s.CIDR] = true
		if s.ScanInterval <= 0 {
			return fmt.Errorf("subnet %q: scan_interval must be > 0", s.CIDR)
		}
		for _, port := range s.Ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("subnet %q: port %d out of range (1–65535)", s.CIDR, port)
			}
		}
		if s.MACAllowlistFile != "" {
			if _, err := os.Stat(s.MACAllowlistFile); err != nil {
				return fmt.Errorf("subnet %q: allowlist file %q: %w", s.CIDR, s.MACAllowlistFile, err)
			}
		}
	}
	return nil
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

	sort.Strings(changes)
	return changes
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
