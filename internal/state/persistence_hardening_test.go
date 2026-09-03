package state

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestBoltStoreRejectsUnsupportedSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := NewBoltStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(keyVersion, []byte("999"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = NewBoltStore(path)
	if err == nil || !strings.Contains(err.Error(), "unsupported schema version") {
		t.Fatalf("NewBoltStore error = %v, want unsupported schema version", err)
	}
}

func TestNewBoltStoreCreatesGroupReadableSecureDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := NewBoltStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o660); got != want {
		t.Fatalf("new database mode = %#o, want %#o", got, want)
	}
}

func TestNewBoltStoreRejectsUnsafeExistingTargets(t *testing.T) {
	t.Run("world-accessible file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.db")
		s, err := NewBoltStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := NewBoltStore(path); err == nil || !strings.Contains(err.Error(), "world-accessible") {
			t.Fatalf("NewBoltStore error = %v, want world-accessible rejection", err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "not-a-db")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := NewBoltStore(path); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("NewBoltStore error = %v, want regular-file rejection", err)
		}
	})
}

func TestBoltStoreSchemaV1AllowsAdditiveRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := NewBoltStore(path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`{"ip":"10.20.0.1","mac":"00:00:5e:00:53:01","last_seen_ns":1}`)
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketHosts).Put([]byte("10.20.0.1"), legacy)
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = NewBoltStore(path)
	if err != nil {
		t.Fatalf("reopen additive v1 record: %v", err)
	}
	defer func() { _ = s.Close() }()
	got, err := s.GetHost(context.Background(), netip.MustParseAddr("10.20.0.1"))
	if err != nil || got == nil || got.Source != "" || !got.MACObservedAt.Equal(time.Unix(0, 1).UTC()) {
		t.Fatalf("additive v1 record = %+v, %v", got, err)
	}
}

func TestBoltStoreLegacyV1DerivesFreshnessWatermarks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := NewBoltStore(path)
	if err != nil {
		t.Fatal(err)
	}
	lastSeen := time.Date(2026, 9, 2, 18, 0, 0, 0, time.UTC)
	legacy := []byte(fmt.Sprintf(`{"ip":"10.20.0.9","mac":"00:00:5e:00:53:09","hostnames":["current.example"],"open_ports":[443],"last_seen_ns":%d}`, lastSeen.UnixNano()))
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketHosts).Put([]byte("10.20.0.9"), legacy)
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = NewBoltStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	ip := netip.MustParseAddr("10.20.0.9")
	olderARP := observedRecord(ip.String(), "00:00:5e:00:53:99", SourceARP, lastSeen.Add(-time.Minute))
	olderDNS := observedRecord(ip.String(), "00:00:5e:00:53:09", SourceDNS, lastSeen.Add(-time.Minute))
	olderDNS.Hostnames = []string{"stale.example"}
	olderDNS.DNSMismatches = []string{}
	olderPorts := observedRecord(ip.String(), "00:00:5e:00:53:09", SourcePort, lastSeen.Add(-time.Minute))
	olderPorts.OpenPorts = []uint16{22}
	for _, stale := range []HostRecord{olderARP, olderDNS, olderPorts} {
		if _, err := s.UpdateHost(ctx, stale); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.GetHost(ctx, ip)
	if err != nil || got == nil {
		t.Fatalf("GetHost = %+v, %v", got, err)
	}
	if got.MAC.String() != "00:00:5e:00:53:09" || len(got.Hostnames) != 1 || got.Hostnames[0] != "current.example" || len(got.OpenPorts) != 1 || got.OpenPorts[0] != 443 {
		t.Fatalf("older legacy update regressed state: %+v", got)
	}
	if !got.MACObservedAt.Equal(lastSeen) || !got.DNSObservedAt.Equal(lastSeen) || !got.PortsObservedAt.Equal(lastSeen) {
		t.Fatalf("legacy watermarks = %+v, want %v", got, lastSeen)
	}
}

func TestBoltStoreCorruptRecordsSurfaceWithoutDeletion(t *testing.T) {
	ctx := context.Background()
	s := openTestBolt(t)
	corruptHostKey := []byte("10.20.0.2")
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketHosts).Put(corruptHostKey, []byte("not-json"))
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetHost(ctx, netip.MustParseAddr("10.20.0.2")); err == nil || !strings.Contains(err.Error(), "corrupt host record") {
		t.Fatalf("GetHost error = %v, want corrupt host record", err)
	}
	if _, err := s.ListHosts(ctx, netip.Prefix{}); err == nil || !strings.Contains(err.Error(), "corrupt host record") {
		t.Fatalf("ListHosts error = %v, want corrupt host record", err)
	}
	if hosts, err := s.ListHosts(ctx, mustParsePrefix("192.0.2.0/24")); err != nil || len(hosts) != 0 {
		t.Fatalf("disjoint ListHosts = %+v, %v; corrupt unrelated host must not poison subnet read", hosts, err)
	}
	if _, err := s.PruneStale(time.Hour); err == nil || !strings.Contains(err.Error(), "corrupt host record") {
		t.Fatalf("PruneStale error = %v, want corrupt host record", err)
	}
	if err := s.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketHosts).Get(corruptHostKey) == nil {
			return errors.New("corrupt host was deleted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketChanges).Put([]byte{0, 0, 0, 0, 0, 0, 0, 1}, []byte("not-json")); err != nil {
			return err
		}
		return tx.Bucket(bucketScanMeta).Put([]byte("10.20.0.0/24/arp"), []byte("not-json"))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecentChanges(ctx, time.Time{}); err == nil || !strings.Contains(err.Error(), "corrupt MAC change") {
		t.Fatalf("RecentChanges error = %v, want corrupt MAC change", err)
	}
	if _, err := s.GetScanMeta(ctx, mustParsePrefix("10.20.0.0/24")); err == nil || !strings.Contains(err.Error(), "corrupt scan metadata") {
		t.Fatalf("GetScanMeta error = %v, want corrupt scan metadata", err)
	}
}

func TestBoltStoreBoundsPersistentChangeHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := newBoltStore(path, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		event := MACIPChange{
			IP:        netip.MustParseAddr(fmt.Sprintf("10.20.0.%d", i)),
			OldMAC:    mustMAC(fmt.Sprintf("00:00:5e:00:53:%02x", i)),
			NewMAC:    mustMAC(fmt.Sprintf("00:00:5e:00:54:%02x", i)),
			Timestamp: time.Unix(int64(i), 0),
		}
		if err := s.RecordMACChange(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	changes, err := s.RecentChanges(ctx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 || changes[0].IP.String() != "10.20.0.2" || changes[1].IP.String() != "10.20.0.3" {
		t.Fatalf("bounded history = %+v, want the newest two events", changes)
	}
}

func TestBoltStoreCanceledContextDoesNotStartWork(t *testing.T) {
	s := openTestBolt(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.GetHost(ctx, netip.MustParseAddr("10.20.0.3")); !errors.Is(err, context.Canceled) {
		t.Fatalf("GetHost error = %v, want context.Canceled", err)
	}
	record := makeTestRecord("10.20.0.3", "00:00:5e:00:53:03")
	if _, err := s.UpdateHost(ctx, record); !errors.Is(err, context.Canceled) {
		t.Fatalf("UpdateHost error = %v, want context.Canceled", err)
	}
	got, err := s.GetHost(context.Background(), record.IP)
	if err != nil || got != nil {
		t.Fatalf("canceled update changed state: %+v, %v", got, err)
	}
}

func TestBoltStoreTransactionRollbackLeavesNoPartialHost(t *testing.T) {
	s := openTestBolt(t)
	ip := netip.MustParseAddr("10.20.0.4")
	rollback := errors.New("rollback")
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketHosts).Put([]byte(ip.String()), []byte(`{"ip":"10.20.0.4"}`)); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("transaction error = %v, want rollback", err)
	}
	got, err := s.GetHost(context.Background(), ip)
	if err != nil || got != nil {
		t.Fatalf("rolled-back transaction persisted host: %+v, %v", got, err)
	}
}

func TestPruneStaleHostsReturnsPreDeleteRecords(t *testing.T) {
	ctx := context.Background()
	for _, backend := range ownershipStores() {
		t.Run(backend.name, func(t *testing.T) {
			store := backend.new(t)
			record := staleRecord("10.20.0.5", "00:00:5e:00:53:05", 2*time.Hour)
			record.Vendor = "example-vendor"
			if _, err := store.UpdateHost(ctx, record); err != nil {
				t.Fatal(err)
			}
			removed, err := store.PruneStaleHosts(time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if len(removed) != 1 || removed[0].IP != record.IP || removed[0].MAC.String() != record.MAC.String() || removed[0].Vendor != record.Vendor {
				t.Fatalf("pre-delete records = %+v, want %+v", removed, record)
			}
			got, err := store.GetHost(ctx, record.IP)
			if err != nil || got != nil {
				t.Fatalf("pruned host remains: %+v, %v", got, err)
			}
		})
	}
}
