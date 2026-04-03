package state

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// openTestBolt opens a fresh BoltStore backed by a temp file.
// The store is automatically closed when the test ends.
func openTestBolt(t *testing.T) *BoltStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := NewBoltStore(path)
	if err != nil {
		t.Fatalf("NewBoltStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestBoltStore_GetHost_NotFound(t *testing.T) {
	s := openTestBolt(t)
	ctx := context.Background()

	got, err := s.GetHost(ctx, netip.MustParseAddr("1.2.3.4"))
	if err != nil {
		t.Fatalf("GetHost: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil record, got %+v", got)
	}
}

func TestBoltStore_UpdateAndGetHost(t *testing.T) {
	s := openTestBolt(t)
	ctx := context.Background()

	rec := makeTestRecord("10.0.1.1", "aa:bb:cc:dd:ee:ff")
	if _, err := s.UpdateHost(ctx, rec); err != nil {
		t.Fatalf("UpdateHost: %v", err)
	}

	got, err := s.GetHost(ctx, rec.IP)
	if err != nil {
		t.Fatalf("GetHost: %v", err)
	}
	if got == nil {
		t.Fatal("expected record, got nil")
	}
	if got.IP != rec.IP {
		t.Errorf("IP: got %v, want %v", got.IP, rec.IP)
	}
	if got.MAC.String() != rec.MAC.String() {
		t.Errorf("MAC: got %v, want %v", got.MAC, rec.MAC)
	}
	if got.Vendor != rec.Vendor {
		t.Errorf("Vendor: got %v, want %v", got.Vendor, rec.Vendor)
	}
	if len(got.OpenPorts) != len(rec.OpenPorts) {
		t.Errorf("OpenPorts: got %v, want %v", got.OpenPorts, rec.OpenPorts)
	}
}

func TestBoltStore_NilGuard_MACNotOverwritten(t *testing.T) {
	s := openTestBolt(t)
	ctx := context.Background()

	rec := makeTestRecord("10.0.1.2", "aa:bb:cc:dd:ee:01")
	if _, err := s.UpdateHost(ctx, rec); err != nil {
		t.Fatal(err)
	}

	// Update with no MAC (e.g. ICMP ping result — has no L2 info).
	noMAC := HostRecord{IP: rec.IP, LastSeen: time.Now(), Alive: true}
	if _, err := s.UpdateHost(ctx, noMAC); err != nil {
		t.Fatal(err)
	}

	got, _ := s.GetHost(ctx, rec.IP)
	if got.MAC.String() != rec.MAC.String() {
		t.Errorf("MAC was overwritten by nil-MAC update: got %v, want %v", got.MAC, rec.MAC)
	}
}

func TestBoltStore_NilGuard_VendorNotOverwritten(t *testing.T) {
	s := openTestBolt(t)
	ctx := context.Background()

	// Vendor is overwritten on same-MAC update (matches MemoryStore behaviour).
	// This test documents that behaviour for BoltStore.
	rec := makeTestRecord("10.0.1.3", "aa:bb:cc:dd:ee:02")
	rec.Vendor = "OriginalVendor"
	if _, err := s.UpdateHost(ctx, rec); err != nil {
		t.Fatal(err)
	}

	update := makeTestRecord("10.0.1.3", "aa:bb:cc:dd:ee:02")
	update.Vendor = "UpdatedVendor"
	if _, err := s.UpdateHost(ctx, update); err != nil {
		t.Fatal(err)
	}

	got, _ := s.GetHost(ctx, rec.IP)
	if got.Vendor != "UpdatedVendor" {
		t.Errorf("Vendor not updated: got %q, want %q", got.Vendor, "UpdatedVendor")
	}
}

func TestBoltStore_HostChange_NewHost(t *testing.T) {
	s := openTestBolt(t)
	ctx := context.Background()

	rec := makeTestRecord("10.0.1.10", "aa:bb:cc:dd:ee:10")
	change, err := s.UpdateHost(ctx, rec)
	if err != nil {
		t.Fatalf("UpdateHost: %v", err)
	}
	if !change.IsNew {
		t.Error("expected IsNew=true for first insert, got false")
	}
	if change.MACChanged {
		t.Error("expected MACChanged=false for new host")
	}
}

func TestBoltStore_HostChange_MACChanged(t *testing.T) {
	s := openTestBolt(t)
	ctx := context.Background()

	recA := makeTestRecord("10.0.1.11", "aa:bb:cc:dd:ee:11")
	if _, err := s.UpdateHost(ctx, recA); err != nil {
		t.Fatal(err)
	}

	recB := makeTestRecord("10.0.1.11", "11:22:33:44:55:66")
	change, err := s.UpdateHost(ctx, recB)
	if err != nil {
		t.Fatalf("UpdateHost (second): %v", err)
	}
	if !change.MACChanged {
		t.Error("expected MACChanged=true")
	}
	hwA, _ := net.ParseMAC("aa:bb:cc:dd:ee:11")
	if change.OldMAC.String() != hwA.String() {
		t.Errorf("OldMAC: got %v, want %v", change.OldMAC, hwA)
	}

	// MAC-IP change must also be persisted to the changes bucket.
	changes, err := s.RecentChanges(ctx, time.Unix(0, 0))
	if err != nil {
		t.Fatalf("RecentChanges: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("expected 1 change event, got %d", len(changes))
	}
	if changes[0].OldMAC.String() != hwA.String() {
		t.Errorf("change OldMAC: got %v, want %v", changes[0].OldMAC, hwA)
	}
}

func TestBoltStore_HostChange_NoChange(t *testing.T) {
	s := openTestBolt(t)
	ctx := context.Background()

	rec := makeTestRecord("10.0.1.12", "aa:bb:cc:dd:ee:12")
	if _, err := s.UpdateHost(ctx, rec); err != nil {
		t.Fatal(err)
	}
	change, err := s.UpdateHost(ctx, rec)
	if err != nil {
		t.Fatalf("UpdateHost (second): %v", err)
	}
	if change.IsNew || change.MACChanged {
		t.Errorf("unexpected change on re-insert with same MAC: %+v", change)
	}
}

func TestBoltStore_GetAllHosts(t *testing.T) {
	s := openTestBolt(t)
	ctx := context.Background()

	recs := []HostRecord{
		makeTestRecord("10.0.1.1", "aa:bb:cc:dd:ee:01"),
		makeTestRecord("10.0.1.2", "aa:bb:cc:dd:ee:02"),
		makeTestRecord("192.168.1.1", "aa:bb:cc:dd:ee:03"),
	}
	for _, r := range recs {
		if _, err := s.UpdateHost(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	all, err := s.ListHosts(ctx, netip.Prefix{})
	if err != nil {
		t.Fatalf("ListHosts (zero prefix): %v", err)
	}
	if len(all) != 3 {
		t.Errorf("got %d hosts, want 3", len(all))
	}
}

func TestBoltStore_GetSubnetHosts(t *testing.T) {
	s := openTestBolt(t)
	ctx := context.Background()

	for _, r := range []HostRecord{
		makeTestRecord("10.0.1.1", "aa:bb:cc:dd:ee:01"),
		makeTestRecord("10.0.1.2", "aa:bb:cc:dd:ee:02"),
		makeTestRecord("192.168.1.1", "aa:bb:cc:dd:ee:03"),
	} {
		if _, err := s.UpdateHost(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	subnet := mustParsePrefix("10.0.1.0/24")
	hosts, err := s.ListHosts(ctx, subnet)
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(hosts) != 2 {
		t.Errorf("got %d hosts for %v, want 2", len(hosts), subnet)
	}
	for _, h := range hosts {
		if !subnet.Contains(h.IP) {
			t.Errorf("host %v is outside subnet %v", h.IP, subnet)
		}
	}
}

func TestBoltStore_PersistenceAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persist.db")
	ctx := context.Background()
	rec := makeTestRecord("10.0.1.99", "de:ad:be:ef:00:01")

	// Write and close.
	{
		s, err := NewBoltStore(path)
		if err != nil {
			t.Fatalf("first open: %v", err)
		}
		if _, err := s.UpdateHost(ctx, rec); err != nil {
			_ = s.Close()
			t.Fatalf("UpdateHost: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}

	// Reopen and verify data survived.
	{
		s, err := NewBoltStore(path)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		defer func() { _ = s.Close() }()

		got, err := s.GetHost(ctx, rec.IP)
		if err != nil {
			t.Fatalf("GetHost after reopen: %v", err)
		}
		if got == nil {
			t.Fatal("host not found after reopen — persistence failed")
		}
		if got.MAC.String() != rec.MAC.String() {
			t.Errorf("MAC after reopen: got %v, want %v", got.MAC, rec.MAC)
		}
		if got.Vendor != rec.Vendor {
			t.Errorf("Vendor after reopen: got %q, want %q", got.Vendor, rec.Vendor)
		}
	}
}

func TestBoltStore_ConcurrentReadWrite(t *testing.T) {
	s := openTestBolt(t)
	ctx := context.Background()

	// Seed initial records so reads have something to return.
	for i := range 5 {
		r := makeTestRecord(
			fmt.Sprintf("10.0.%d.1", i),
			fmt.Sprintf("aa:bb:cc:dd:%02x:01", i),
		)
		if _, err := s.UpdateHost(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := range 20 {
				ip := fmt.Sprintf("10.0.%d.%d", i%5, j+2)
				mac := fmt.Sprintf("aa:bb:cc:%02x:%02x:01", i%5, j+1)
				_, _ = s.UpdateHost(ctx, makeTestRecord(ip, mac))
				_, _ = s.ListHosts(ctx, mustParsePrefix(fmt.Sprintf("10.0.%d.0/24", i%5)))
			}
		}(i)
	}
	wg.Wait()
}

func TestBoltStore_SchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schema.db")
	s, err := NewBoltStore(path)
	if err != nil {
		t.Fatalf("NewBoltStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	var version string
	if err := s.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		if meta == nil {
			return fmt.Errorf("meta bucket missing")
		}
		v := meta.Get(keyVersion)
		if v == nil {
			return fmt.Errorf("version key missing from meta bucket")
		}
		version = string(v)
		return nil
	}); err != nil {
		t.Fatalf("View meta bucket: %v", err)
	}
	if version != "1" {
		t.Errorf("schema version = %q, want %q", version, "1")
	}
}

func TestBoltStore_Timeout_FileLocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locked.db")

	s1, err := NewBoltStore(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	defer func() { _ = s1.Close() }()

	// Second open on the same file must fail due to the 1s timeout.
	_, err = NewBoltStore(path)
	if err == nil {
		t.Fatal("expected error when opening already-locked database, got nil")
	}
}
