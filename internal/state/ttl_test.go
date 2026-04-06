package state

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"testing"
	"time"
)

// staleRecord returns a HostRecord whose LastSeen is in the past by the given offset.
func staleRecord(ip, mac string, age time.Duration) HostRecord {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		panic("invalid MAC: " + err.Error())
	}
	return HostRecord{
		IP:       netip.MustParseAddr(ip),
		MAC:      hw,
		LastSeen: time.Now().Add(-age),
		Alive:    true,
	}
}

// --- Memory backend TTL tests ---

func TestPruneStaleMemory_RemovesOldHosts(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	ttl := 5 * time.Minute

	// Insert one stale host (last seen 10 minutes ago) and one fresh host.
	stale := staleRecord("10.0.0.1", "aa:bb:cc:dd:ee:01", 10*time.Minute)
	fresh := staleRecord("10.0.0.2", "aa:bb:cc:dd:ee:02", 1*time.Minute)

	if _, err := store.UpdateHost(ctx, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateHost(ctx, fresh); err != nil {
		t.Fatal(err)
	}

	removed, err := store.PruneStale(ttl)
	if err != nil {
		t.Fatalf("PruneStale: %v", err)
	}
	if len(removed) != 1 || removed[0] != "10.0.0.1" {
		t.Errorf("expected [10.0.0.1] removed, got %v", removed)
	}

	// Stale host must be gone.
	r, err := store.GetHost(ctx, netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if r != nil {
		t.Error("stale host still present after PruneStale")
	}

	// Fresh host must still be present.
	r, err = store.GetHost(ctx, netip.MustParseAddr("10.0.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Error("fresh host was unexpectedly pruned")
	}
}

func TestPruneStaleMemory_PreservesRecentHosts(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	ttl := 5 * time.Minute

	// All hosts are recent.
	for i := 1; i <= 3; i++ {
		ip := netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}).String()
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, byte(i)}.String()
		if _, err := store.UpdateHost(ctx, staleRecord(ip, mac, 1*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}

	removed, err := store.PruneStale(ttl)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Errorf("expected no hosts pruned, got %v", removed)
	}
	if store.HostCount() != 3 {
		t.Errorf("expected 3 hosts remaining, got %d", store.HostCount())
	}
}

func TestPruneStaleMemory_ReturnsPrunedIPs(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	ttl := 5 * time.Minute

	staleIPs := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for i, ip := range staleIPs {
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, byte(i + 1)}.String()
		if _, err := store.UpdateHost(ctx, staleRecord(ip, mac, 10*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}

	removed, err := store.PruneStale(ttl)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != len(staleIPs) {
		t.Errorf("expected %d removed, got %d: %v", len(staleIPs), len(removed), removed)
	}
	sort.Strings(removed)
	sort.Strings(staleIPs)
	for i, ip := range staleIPs {
		if removed[i] != ip {
			t.Errorf("removed[%d] = %q, want %q", i, removed[i], ip)
		}
	}
}

func TestPruneStaleMemory_EmptyStore(t *testing.T) {
	store := NewMemoryStore()
	removed, err := store.PruneStale(5 * time.Minute)
	if err != nil {
		t.Fatalf("PruneStale on empty store: %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("expected nil/empty removed slice, got %v", removed)
	}
}

func TestPruneStaleInvalidTTL(t *testing.T) {
	store := NewMemoryStore()

	_, err := store.PruneStale(0)
	if err == nil {
		t.Error("expected error for zero TTL, got nil")
	}

	_, err = store.PruneStale(-1 * time.Second)
	if err == nil {
		t.Error("expected error for negative TTL, got nil")
	}
}

func TestUpdateHostSetsLastSeen(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	before := time.Now()
	rec := HostRecord{
		IP:       netip.MustParseAddr("10.0.0.1"),
		MAC:      net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
		LastSeen: time.Now(),
		Alive:    true,
	}
	if _, err := store.UpdateHost(ctx, rec); err != nil {
		t.Fatal(err)
	}
	after := time.Now()

	r, err := store.GetHost(ctx, netip.MustParseAddr("10.0.0.1"))
	if err != nil || r == nil {
		t.Fatal("GetHost failed or returned nil")
	}
	if r.LastSeen.Before(before) || r.LastSeen.After(after.Add(time.Second)) {
		t.Errorf("LastSeen %v is not within expected range [%v, %v]", r.LastSeen, before, after)
	}
}

// --- Bolt backend TTL tests ---

func TestPruneStaleBolt_RemovesOldHosts(t *testing.T) {
	ctx := context.Background()
	store := openTestBolt(t)
	ttl := 5 * time.Minute

	stale := staleRecord("10.0.0.1", "aa:bb:cc:dd:ee:01", 10*time.Minute)
	fresh := staleRecord("10.0.0.2", "aa:bb:cc:dd:ee:02", 1*time.Minute)

	if _, err := store.UpdateHost(ctx, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateHost(ctx, fresh); err != nil {
		t.Fatal(err)
	}

	removed, err := store.PruneStale(ttl)
	if err != nil {
		t.Fatalf("PruneStale bolt: %v", err)
	}
	if len(removed) != 1 || removed[0] != "10.0.0.1" {
		t.Errorf("expected [10.0.0.1] removed, got %v", removed)
	}

	r, err := store.GetHost(ctx, netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if r != nil {
		t.Error("stale host still present after PruneStale (bolt)")
	}

	r, err = store.GetHost(ctx, netip.MustParseAddr("10.0.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Error("fresh host was unexpectedly pruned (bolt)")
	}
}

func TestPruneStaleBolt_PreservesRecentHosts(t *testing.T) {
	ctx := context.Background()
	store := openTestBolt(t)
	ttl := 5 * time.Minute

	for i := 1; i <= 3; i++ {
		ip := netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}).String()
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, byte(i)}.String()
		if _, err := store.UpdateHost(ctx, staleRecord(ip, mac, 1*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}

	removed, err := store.PruneStale(ttl)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Errorf("expected no hosts pruned (bolt), got %v", removed)
	}
}

func TestPruneStaleBolt_ReturnsPrunedIPs(t *testing.T) {
	ctx := context.Background()
	store := openTestBolt(t)
	ttl := 5 * time.Minute

	staleIPs := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for i, ip := range staleIPs {
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, byte(i + 1)}.String()
		if _, err := store.UpdateHost(ctx, staleRecord(ip, mac, 10*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}

	removed, err := store.PruneStale(ttl)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != len(staleIPs) {
		t.Errorf("expected %d removed (bolt), got %d: %v", len(staleIPs), len(removed), removed)
	}
	sort.Strings(removed)
	sort.Strings(staleIPs)
	for i, ip := range staleIPs {
		if removed[i] != ip {
			t.Errorf("removed[%d] = %q, want %q (bolt)", i, removed[i], ip)
		}
	}
}
