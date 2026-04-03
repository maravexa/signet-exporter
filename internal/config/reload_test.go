package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeRC(subnets ...ReloadableSubnet) ReloadableConfig {
	return ReloadableConfig{Subnets: subnets}
}

func makeRS(cidr string, interval time.Duration, ports ...int) ReloadableSubnet {
	return ReloadableSubnet{CIDR: cidr, ScanInterval: interval, Ports: ports}
}

// --- Diff tests ---

func TestDiff_NoChanges(t *testing.T) {
	rc := makeRC(
		makeRS("10.0.1.0/24", 60*time.Second, 22, 443),
		makeRS("10.0.2.0/24", 5*time.Minute),
	)
	changes := Diff(rc, rc)
	if len(changes) != 0 {
		t.Errorf("expected no changes for identical configs, got %v", changes)
	}
}

func TestDiff_SubnetAdded(t *testing.T) {
	old := makeRC(makeRS("10.0.1.0/24", 60*time.Second))
	new := makeRC(
		makeRS("10.0.1.0/24", 60*time.Second),
		makeRS("10.0.2.0/24", 2*time.Minute),
	)
	changes := Diff(old, new)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d: %v", len(changes), changes)
	}
	if changes[0] != "subnet 10.0.2.0/24: added" {
		t.Errorf("unexpected change: %q", changes[0])
	}
}

func TestDiff_SubnetRemoved(t *testing.T) {
	old := makeRC(
		makeRS("10.0.1.0/24", 60*time.Second),
		makeRS("10.0.3.0/24", 30*time.Second),
	)
	new := makeRC(makeRS("10.0.1.0/24", 60*time.Second))
	changes := Diff(old, new)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d: %v", len(changes), changes)
	}
	if changes[0] != "subnet 10.0.3.0/24: removed" {
		t.Errorf("unexpected change: %q", changes[0])
	}
}

func TestDiff_IntervalChanged(t *testing.T) {
	old := makeRC(makeRS("10.0.1.0/24", 60*time.Second))
	new := makeRC(makeRS("10.0.1.0/24", 30*time.Second))
	changes := Diff(old, new)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d: %v", len(changes), changes)
	}
	if changes[0] != "subnet 10.0.1.0/24: scan_interval 1m0s → 30s" {
		t.Errorf("unexpected change: %q", changes[0])
	}
}

func TestDiff_PortsChanged(t *testing.T) {
	old := makeRC(makeRS("10.0.1.0/24", 60*time.Second, 22, 80))
	new := makeRC(makeRS("10.0.1.0/24", 60*time.Second, 22, 443))
	changes := Diff(old, new)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d: %v", len(changes), changes)
	}
	if changes[0] != "subnet 10.0.1.0/24: ports changed" {
		t.Errorf("unexpected change: %q", changes[0])
	}
}

func TestDiff_AllowlistChanged(t *testing.T) {
	old := makeRC(ReloadableSubnet{
		CIDR:             "10.0.1.0/24",
		ScanInterval:     60 * time.Second,
		MACAllowlistFile: "/etc/signet/allowlists/prod.txt",
	})
	new := makeRC(ReloadableSubnet{
		CIDR:             "10.0.1.0/24",
		ScanInterval:     60 * time.Second,
		MACAllowlistFile: "/etc/signet/allowlists/prod2.txt",
	})
	changes := Diff(old, new)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d: %v", len(changes), changes)
	}
	if changes[0] != "subnet 10.0.1.0/24: allowlist /etc/signet/allowlists/prod.txt → /etc/signet/allowlists/prod2.txt" {
		t.Errorf("unexpected change: %q", changes[0])
	}
}

// --- ExtractReloadable ---

func TestExtractReloadable(t *testing.T) {
	cfg := &Config{
		Subnets: []SubnetConfig{
			{CIDR: "10.0.1.0/24", ScanInterval: 60 * time.Second, Ports: []uint16{22, 443}, MACAllowlistFile: "/tmp/al.txt"},
			{CIDR: "10.0.2.0/24", ScanInterval: 5 * time.Minute},
		},
	}
	rc := ExtractReloadable(cfg)
	if len(rc.Subnets) != 2 {
		t.Fatalf("expected 2 subnets, got %d", len(rc.Subnets))
	}
	s0 := rc.Subnets[0]
	if s0.CIDR != "10.0.1.0/24" {
		t.Errorf("CIDR = %q, want 10.0.1.0/24", s0.CIDR)
	}
	if s0.ScanInterval != 60*time.Second {
		t.Errorf("ScanInterval = %v, want 60s", s0.ScanInterval)
	}
	if len(s0.Ports) != 2 || s0.Ports[0] != 22 || s0.Ports[1] != 443 {
		t.Errorf("Ports = %v, want [22 443]", s0.Ports)
	}
	if s0.MACAllowlistFile != "/tmp/al.txt" {
		t.Errorf("MACAllowlistFile = %q, want /tmp/al.txt", s0.MACAllowlistFile)
	}
	if rc.Subnets[1].CIDR != "10.0.2.0/24" {
		t.Errorf("second CIDR = %q, want 10.0.2.0/24", rc.Subnets[1].CIDR)
	}
}

// --- ValidateReloadable ---

func TestValidateReloadable_Valid(t *testing.T) {
	rc := makeRC(
		makeRS("10.0.1.0/24", 60*time.Second, 22, 443),
		makeRS("10.0.2.0/24", 5*time.Minute),
	)
	if err := ValidateReloadable(rc); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateReloadable_InvalidCIDR(t *testing.T) {
	rc := makeRC(ReloadableSubnet{CIDR: "not-a-cidr", ScanInterval: 60 * time.Second})
	if err := ValidateReloadable(rc); err == nil {
		t.Error("expected error for invalid CIDR, got nil")
	}
}

func TestValidateReloadable_InvalidPort(t *testing.T) {
	rc := makeRC(ReloadableSubnet{CIDR: "10.0.1.0/24", ScanInterval: 60 * time.Second, Ports: []int{70000}})
	if err := ValidateReloadable(rc); err == nil {
		t.Error("expected error for port > 65535, got nil")
	}
}

func TestValidateReloadable_MissingAllowlistFile(t *testing.T) {
	rc := makeRC(ReloadableSubnet{
		CIDR:             "10.0.1.0/24",
		ScanInterval:     60 * time.Second,
		MACAllowlistFile: "/does/not/exist/allowlist.txt",
	})
	if err := ValidateReloadable(rc); err == nil {
		t.Error("expected error for non-existent allowlist file, got nil")
	}
}

// TestValidateReloadable_ExistingAllowlistFile verifies that a real allowlist
// file path passes validation (complements the missing-file test above).
func TestValidateReloadable_ExistingAllowlistFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "allowlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	rc := makeRC(ReloadableSubnet{
		CIDR:             "10.0.1.0/24",
		ScanInterval:     60 * time.Second,
		MACAllowlistFile: filepath.Clean(f.Name()),
	})
	if err := ValidateReloadable(rc); err != nil {
		t.Errorf("unexpected error for existing allowlist file: %v", err)
	}
}
