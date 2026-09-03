package state

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Bucket names and fixed keys used throughout the bolt store.
var (
	bucketHosts    = []byte("hosts")
	bucketChanges  = []byte("changes")
	bucketScanMeta = []byte("scanmeta")
	bucketMeta     = []byte("meta")
	keyVersion     = []byte("version")
	schemaVersion  = []byte("1")
)

// DefaultMaxChanges bounds the retained MAC-IP binding history in both store
// implementations. It limits disk growth while keeping recent audit context.
const DefaultMaxChanges = 10000

// BoltStore is a bbolt-backed persistent Store implementation.
//
// Bucket layout:
//
//	"hosts"    → key: IP string     → value: JSON hostRecordJSON
//	"changes"  → key: 8-byte big-endian sequence → value: JSON macIPChangeJSON
//	"scanmeta" → key: "subnet/scanner" → value: JSON scanMetaJSON
//	"meta"     → key: "version"     → value: schema version ("1")
type BoltStore struct {
	db         *bolt.DB
	maxChanges int
}

// NewBoltStore opens or creates the bbolt database at path.
// File mode 0o660 (owner+group rw). Timeout 1s — fail fast if another process
// holds the lock (i.e. another signet-exporter instance is running).
// Creates all required buckets and writes schema version on first open. Schema
// v1 is additive: absent JSON fields are accepted as legacy v1 records, while
// any explicit version other than v1 is rejected before normal operation.
func NewBoltStore(path string) (*BoltStore, error) {
	return newBoltStore(path, DefaultMaxChanges)
}

// newBoltStore allows package tests to exercise retention behavior with a
// small limit. Production callers use NewBoltStore and DefaultMaxChanges.
func newBoltStore(path string, maxChanges int) (*BoltStore, error) {
	if maxChanges <= 0 {
		maxChanges = DefaultMaxChanges
	}
	info, statErr := os.Lstat(path)
	created := os.IsNotExist(statErr)
	if statErr != nil && !created {
		return nil, fmt.Errorf("stat bolt db %q: %w", path, statErr)
	}
	if !created {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("bolt db %q must be a regular file, got %s", path, info.Mode().Type())
		}
		if info.Mode().Perm()&0o007 != 0 {
			return nil, fmt.Errorf("bolt db %q is world-accessible (mode %#o)", path, info.Mode().Perm())
		}
	}
	opts := &bolt.Options{Timeout: time.Second}
	db, err := bolt.Open(path, 0o660, opts) //nolint:gosec // G304: path is operator-supplied config, not user input
	if err != nil {
		return nil, fmt.Errorf("open bolt db %q: %w", path, err)
	}

	if created {
		if err := os.Chmod(path, 0o660); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("set bolt db permissions %q: %w", path, err)
		}
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists(bucketMeta)
		if err != nil {
			return fmt.Errorf("create bucket %q: %w", bucketMeta, err)
		}
		version := meta.Get(keyVersion)
		if version == nil {
			if err := meta.Put(keyVersion, schemaVersion); err != nil {
				return fmt.Errorf("write schema version: %w", err)
			}
		} else if !bytes.Equal(version, schemaVersion) {
			return fmt.Errorf("unsupported schema version %q (supported: %q)", version, schemaVersion)
		}
		for _, name := range [][]byte{bucketHosts, bucketChanges, bucketScanMeta} {
			if _, berr := tx.CreateBucketIfNotExists(name); berr != nil {
				return fmt.Errorf("create bucket %q: %w", name, berr)
			}
		}
		return resetSessionGenerationsTx(tx)
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init bolt schema: %w", err)
	}

	return &BoltStore{db: db, maxChanges: maxChanges}, nil
}

// resetSessionGenerationsTx clears process-local configuration-generation
// floors on every durable-store open. Scheduler generations intentionally
// restart from a small counter after process restart, so persisting a prior
// process's floor would reject all fresh port/authorization observations. The
// actual historical values remain available to collectors until revalidation.
func resetSessionGenerationsTx(tx *bolt.Tx) error {
	hosts := tx.Bucket(bucketHosts)
	type replacement struct {
		key  []byte
		data []byte
	}
	replacements := make([]replacement, 0)
	if err := hosts.ForEach(func(k, v []byte) error {
		host, err := unmarshalHostRecord(v)
		if err != nil {
			return fmt.Errorf("corrupt host record %q: %w", k, err)
		}
		if host.PortsGeneration == 0 && host.AuthorizationGeneration == 0 {
			return nil
		}
		host.PortsGeneration = 0
		host.AuthorizationGeneration = 0
		data, err := marshalHostRecord(host)
		if err != nil {
			return fmt.Errorf("normalize host record %q: %w", k, err)
		}
		key := append([]byte(nil), k...)
		replacements = append(replacements, replacement{key: key, data: data})
		return nil
	}); err != nil {
		return err
	}
	for _, replacement := range replacements {
		if err := hosts.Put(replacement.key, replacement.data); err != nil {
			return fmt.Errorf("reset session generation %q: %w", replacement.key, err)
		}
	}
	return nil
}

// PruneStale removes all hosts whose LastSeen is older than ttl.
// Uses a single read-write transaction so the prune is atomic — no concurrent
// UpdateHost can resurrect a host between the stale check and the delete.
// Returns the IPs of removed hosts, or an error if ttl is invalid or the transaction fails.
func (b *BoltStore) PruneStale(ttl time.Duration) ([]string, error) {
	removedHosts, err := b.PruneStaleHosts(ttl)
	if err != nil {
		return nil, err
	}
	removed := make([]string, len(removedHosts))
	for i, host := range removedHosts {
		removed[i] = host.IP.String()
	}
	return removed, nil
}

// PruneStaleHosts removes stale hosts and returns their pre-delete records in
// the same write transaction. Corrupt records abort the transaction and are
// left untouched so operators can repair or inspect the database.
func (b *BoltStore) PruneStaleHosts(ttl time.Duration) ([]HostRecord, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("invalid TTL: %v", ttl)
	}
	removed := make([]HostRecord, 0)
	err := b.db.Update(func(tx *bolt.Tx) error {
		hBkt := tx.Bucket(bucketHosts)
		var staleKeys [][]byte
		if err := hBkt.ForEach(func(k, v []byte) error {
			r, rerr := unmarshalHostRecord(v)
			if rerr != nil {
				return fmt.Errorf("corrupt host record %q: %w", k, rerr)
			}
			ip, ipErr := netip.ParseAddr(string(k))
			if ipErr != nil {
				return fmt.Errorf("corrupt host key %q: %w", k, ipErr)
			}
			if r.IP != ip {
				return fmt.Errorf("corrupt host record %q: embedded IP is %q", k, r.IP)
			}
			if IsStale(r.LastSeen, ttl) {
				// Copy key — ForEach keys are only valid inside the callback.
				keyCopy := make([]byte, len(k))
				copy(keyCopy, k)
				staleKeys = append(staleKeys, keyCopy)
				removed = append(removed, copyHostRecord(&r))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range staleKeys {
			if err := hBkt.Delete(k); err != nil {
				return fmt.Errorf("delete stale host %q: %w", k, err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return removed, nil
}

// Close closes the underlying bbolt database.
func (b *BoltStore) Close() error {
	return b.db.Close()
}

// ---- JSON wire types -------------------------------------------------------

// hostRecordJSON is the on-disk representation of HostRecord.
// net.HardwareAddr values are stored as colon-separated hex MAC strings.
type hostRecordJSON struct {
	IP                      string   `json:"ip"`
	Source                  string   `json:"source,omitempty"`
	ObservedAt              int64    `json:"observed_at_ns,omitempty"`
	ConfigGeneration        uint64   `json:"config_generation,omitempty"`
	MAC                     string   `json:"mac,omitempty"`
	Vendor                  string   `json:"vendor,omitempty"`
	Hostnames               []string `json:"hostnames"`
	DNSMismatches           []string `json:"dns_mismatches"`
	FirstSeen               int64    `json:"first_seen_ns"`
	LastSeen                int64    `json:"last_seen_ns"`
	OpenPorts               []uint16 `json:"open_ports"`
	DuplicateMACs           []string `json:"duplicate_macs,omitempty"`
	Alive                   bool     `json:"alive"`
	Authorized              bool     `json:"authorized"`
	AuthorizationChecked    bool     `json:"authorization_checked"`
	AuthorizationScope      string   `json:"authorization_scope,omitempty"`
	DuplicateChecked        bool     `json:"duplicate_checked"`
	MACChangeCount          uint64   `json:"mac_change_count"`
	MACObservedAt           int64    `json:"mac_observed_at_ns,omitempty"`
	DNSObservedAt           int64    `json:"dns_observed_at_ns,omitempty"`
	PortsObservedAt         int64    `json:"ports_observed_at_ns,omitempty"`
	AuthorizationObservedAt int64    `json:"authorization_observed_at_ns,omitempty"`
	PortsGeneration         uint64   `json:"ports_generation,omitempty"`
	AuthorizationGeneration uint64   `json:"authorization_generation,omitempty"`
}

type macIPChangeJSON struct {
	IP        string `json:"ip"`
	OldMAC    string `json:"old_mac"`
	NewMAC    string `json:"new_mac"`
	Timestamp int64  `json:"timestamp_ns"` // UnixNano
}

type scanMetaJSON struct {
	Subnet     string `json:"subnet"`
	Scanner    string `json:"scanner"`
	DurationNS int64  `json:"duration_ns"`
	Timestamp  int64  `json:"timestamp_ns"` // UnixNano
	Error      bool   `json:"error"`
	ErrorCount uint64 `json:"error_count"`
}

// ---- serialization helpers -------------------------------------------------

func marshalHostRecord(r HostRecord) ([]byte, error) {
	j := hostRecordJSON{
		IP:                      r.IP.String(),
		Source:                  string(r.Source),
		ObservedAt:              unixNanoOrZero(r.ObservedAt),
		ConfigGeneration:        r.ConfigGeneration,
		Vendor:                  r.Vendor,
		Hostnames:               r.Hostnames,
		DNSMismatches:           r.DNSMismatches,
		FirstSeen:               unixNanoOrZero(r.FirstSeen),
		LastSeen:                unixNanoOrZero(r.LastSeen),
		OpenPorts:               r.OpenPorts,
		Alive:                   r.Alive,
		Authorized:              r.Authorized,
		AuthorizationChecked:    r.AuthorizationChecked,
		AuthorizationScope:      r.AuthorizationScope,
		DuplicateChecked:        r.DuplicateChecked,
		MACChangeCount:          r.MACChangeCount,
		MACObservedAt:           unixNanoOrZero(r.MACObservedAt),
		DNSObservedAt:           unixNanoOrZero(r.DNSObservedAt),
		PortsObservedAt:         unixNanoOrZero(r.PortsObservedAt),
		AuthorizationObservedAt: unixNanoOrZero(r.AuthorizationObservedAt),
		PortsGeneration:         r.PortsGeneration,
		AuthorizationGeneration: r.AuthorizationGeneration,
	}
	if len(r.MAC) > 0 {
		j.MAC = r.MAC.String()
	}
	if len(r.DuplicateMACs) > 0 {
		j.DuplicateMACs = make([]string, len(r.DuplicateMACs))
		for i, m := range r.DuplicateMACs {
			j.DuplicateMACs[i] = m.String()
		}
	}
	return json.Marshal(j)
}

func unixNanoOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func timeFromUnixNano(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns).UTC()
}

func unmarshalHostRecord(data []byte) (HostRecord, error) {
	var j hostRecordJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return HostRecord{}, err
	}
	ip, err := netip.ParseAddr(j.IP)
	if err != nil {
		return HostRecord{}, fmt.Errorf("parse IP %q: %w", j.IP, err)
	}
	r := HostRecord{
		IP:                      ip,
		Source:                  ObservationSource(j.Source),
		ObservedAt:              timeFromUnixNano(j.ObservedAt),
		ConfigGeneration:        j.ConfigGeneration,
		Vendor:                  j.Vendor,
		Hostnames:               j.Hostnames,
		DNSMismatches:           j.DNSMismatches,
		FirstSeen:               timeFromUnixNano(j.FirstSeen),
		LastSeen:                timeFromUnixNano(j.LastSeen),
		OpenPorts:               j.OpenPorts,
		Alive:                   j.Alive,
		Authorized:              j.Authorized,
		AuthorizationChecked:    j.AuthorizationChecked,
		AuthorizationScope:      j.AuthorizationScope,
		DuplicateChecked:        j.DuplicateChecked,
		MACChangeCount:          j.MACChangeCount,
		MACObservedAt:           timeFromUnixNano(j.MACObservedAt),
		DNSObservedAt:           timeFromUnixNano(j.DNSObservedAt),
		PortsObservedAt:         timeFromUnixNano(j.PortsObservedAt),
		AuthorizationObservedAt: timeFromUnixNano(j.AuthorizationObservedAt),
		PortsGeneration:         j.PortsGeneration,
		AuthorizationGeneration: j.AuthorizationGeneration,
	}
	if !validObservationSource(r.Source) {
		return HostRecord{}, fmt.Errorf("unknown observation source %q", r.Source)
	}
	if j.MAC != "" {
		mac, merr := net.ParseMAC(j.MAC)
		if merr != nil {
			return HostRecord{}, fmt.Errorf("parse MAC %q: %w", j.MAC, merr)
		}
		r.MAC = mac
	}
	if len(j.DuplicateMACs) > 0 {
		r.DuplicateMACs = make([]net.HardwareAddr, len(j.DuplicateMACs))
		for i, s := range j.DuplicateMACs {
			mac, merr := net.ParseMAC(s)
			if merr != nil {
				return HostRecord{}, fmt.Errorf("parse duplicate MAC %q: %w", s, merr)
			}
			r.DuplicateMACs[i] = mac
		}
	}
	deriveLegacyWatermarks(&r)
	return r, nil
}

// deriveLegacyWatermarks protects records written before source-owned
// watermarks existed. Old v1 JSON omitted those fields, so LastSeen is the only
// conservative ordering evidence available. We apply it only to populated
// fields; this may reject a legitimately delayed first enrichment after an
// upgrade, but never lets an ambiguous older observation regress persisted
// inventory. The normalized fields are written on the next successful update.
func deriveLegacyWatermarks(r *HostRecord) {
	if r.LastSeen.IsZero() {
		return
	}
	if r.MACObservedAt.IsZero() && len(r.MAC) > 0 {
		r.MACObservedAt = r.LastSeen
	}
	if r.DNSObservedAt.IsZero() && (len(r.Hostnames) > 0 || len(r.DNSMismatches) > 0) {
		r.DNSObservedAt = r.LastSeen
	}
	if r.PortsObservedAt.IsZero() && len(r.OpenPorts) > 0 {
		r.PortsObservedAt = r.LastSeen
	}
	if r.AuthorizationObservedAt.IsZero() && r.AuthorizationChecked {
		r.AuthorizationObservedAt = r.LastSeen
	}
}

// appendChangeTx writes a MACIPChange into the bounded persistent history.
// Must be called inside a write transaction.
func appendChangeTx(tx *bolt.Tx, event MACIPChange, maxChanges int) error {
	bkt := tx.Bucket(bucketChanges)
	seq, err := bkt.NextSequence()
	if err != nil {
		return fmt.Errorf("next sequence: %w", err)
	}
	j := macIPChangeJSON{
		IP:        event.IP.String(),
		OldMAC:    event.OldMAC.String(),
		NewMAC:    event.NewMAC.String(),
		Timestamp: event.Timestamp.UnixNano(),
	}
	data, merr := json.Marshal(j)
	if merr != nil {
		return merr
	}
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], seq)
	if err := bkt.Put(key[:], data); err != nil {
		return err
	}
	if maxChanges <= 0 {
		maxChanges = DefaultMaxChanges
	}
	count := 0
	if err := bkt.ForEach(func(_, _ []byte) error {
		count++
		return nil
	}); err != nil {
		return fmt.Errorf("count MAC changes: %w", err)
	}
	for excess := count - maxChanges; excess > 0; excess-- {
		k, _ := bkt.Cursor().First()
		if k == nil {
			break
		}
		if err := bkt.Delete(k); err != nil {
			return fmt.Errorf("prune oldest MAC change: %w", err)
		}
	}
	return nil
}

// ---- Store interface implementation ----------------------------------------

// UpdateHost inserts or updates a host record and reports what changed.
// The entire read-modify-write is performed atomically inside a single db.Update.
func (b *BoltStore) UpdateHost(ctx context.Context, record HostRecord) (HostChange, error) {
	if err := contextErr(ctx); err != nil {
		return HostChange{}, err
	}
	if !validObservationSource(record.Source) {
		return HostChange{}, fmt.Errorf("unknown observation source %q", record.Source)
	}
	var change HostChange
	err := b.db.Update(func(tx *bolt.Tx) error {
		hBkt := tx.Bucket(bucketHosts)
		key := []byte(record.IP.String())
		data := hBkt.Get(key)

		// ---- new host -------------------------------------------------------
		if data == nil {
			if !sourceCanCreateHost(record.Source) {
				// DNS/port/authorization observations are enrichment of an existing
				// host and cannot resurrect a record removed by TTL eviction.
				return nil
			}
			r := newObservedHost(record)
			encoded, err := marshalHostRecord(r)
			if err != nil {
				return err
			}
			change = HostChange{
				Applied:           true,
				IsNew:             true,
				DuplicateDetected: record.DuplicateChecked && len(record.DuplicateMACs) > 0,
			}
			return hBkt.Put(key, encoded)
		}

		existing, err := unmarshalHostRecord(data)
		if err != nil {
			return fmt.Errorf("unmarshal existing host %s: %w", record.IP, err)
		}

		hostChange, macIPChange, applied := applyHostObservation(&existing, record)
		if !applied {
			change = hostChange
			return nil
		}
		hostChange.Applied = true
		if macIPChange != nil {
			if err := appendChangeTx(tx, *macIPChange, b.maxChanges); err != nil {
				return err
			}
		}
		encoded, err := marshalHostRecord(existing)
		if err != nil {
			return err
		}
		change = hostChange
		return hBkt.Put(key, encoded)
	})
	return change, err
}

// GetHost retrieves a host record by IP address.
// Returns nil, nil if the host is not found.
func (b *BoltStore) GetHost(ctx context.Context, ip netip.Addr) (*HostRecord, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	var result *HostRecord
	err := b.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketHosts).Get([]byte(ip.String()))
		if data == nil {
			return nil
		}
		r, rerr := unmarshalHostRecord(data)
		if rerr != nil {
			return fmt.Errorf("corrupt host record %q: %w", ip, rerr)
		}
		if r.IP != ip {
			return fmt.Errorf("corrupt host record %q: embedded IP is %q", ip, r.IP)
		}
		result = &r
		return nil
	})
	return result, err
}

// ListHosts returns all host records within the given subnet prefix.
// If subnet is the zero prefix, all hosts are returned.
// Always returns a non-nil slice.
func (b *BoltStore) ListHosts(ctx context.Context, subnet netip.Prefix) ([]HostRecord, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	result := make([]HostRecord, 0)
	zeroPrefix := netip.Prefix{}
	err := b.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketHosts).ForEach(func(k, v []byte) error {
			if err := contextErr(ctx); err != nil {
				return err
			}
			ip, perr := netip.ParseAddr(string(k))
			if perr != nil {
				return fmt.Errorf("corrupt host key %q: %w", k, perr)
			}
			if subnet != zeroPrefix && !subnet.Contains(ip) {
				return nil
			}
			r, rerr := unmarshalHostRecord(v)
			if rerr != nil {
				return fmt.Errorf("corrupt host record %q: %w", k, rerr)
			}
			if r.IP != ip {
				return fmt.Errorf("corrupt host record %q: embedded IP is %q", k, r.IP)
			}
			result = append(result, r)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// RecordMACChange appends a MAC-IP change event to persistent storage.
func (b *BoltStore) RecordMACChange(ctx context.Context, event MACIPChange) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	return b.db.Update(func(tx *bolt.Tx) error {
		return appendChangeTx(tx, event, b.maxChanges)
	})
}

// RecentChanges returns all MAC-IP change events at or after the given time.
func (b *BoltStore) RecentChanges(ctx context.Context, since time.Time) ([]MACIPChange, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	sinceNS := since.UnixNano()
	result := make([]MACIPChange, 0)
	err := b.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketChanges).ForEach(func(k, v []byte) error {
			if err := contextErr(ctx); err != nil {
				return err
			}
			var j macIPChangeJSON
			if err := json.Unmarshal(v, &j); err != nil {
				return fmt.Errorf("corrupt MAC change %x: %w", k, err)
			}
			ip, err := netip.ParseAddr(j.IP)
			if err != nil {
				return fmt.Errorf("corrupt MAC change %x IP %q: %w", k, j.IP, err)
			}
			oldMAC, err := net.ParseMAC(j.OldMAC)
			if err != nil {
				return fmt.Errorf("corrupt MAC change %x old MAC %q: %w", k, j.OldMAC, err)
			}
			newMAC, err := net.ParseMAC(j.NewMAC)
			if err != nil {
				return fmt.Errorf("corrupt MAC change %x new MAC %q: %w", k, j.NewMAC, err)
			}
			if j.Timestamp < sinceNS {
				return nil
			}
			result = append(result, MACIPChange{
				IP:        ip,
				OldMAC:    oldMAC,
				NewMAC:    newMAC,
				Timestamp: time.Unix(0, j.Timestamp).UTC(),
			})
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// RecordScanMeta stores timing metadata for a subnet/scanner pair.
// ErrorCount is a cumulative monotonic counter: preserved across updates,
// incremented when meta.Error is true — matching MemoryStore semantics.
func (b *BoltStore) RecordScanMeta(ctx context.Context, meta ScanMeta) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	return b.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bucketScanMeta)
		key := []byte(meta.Subnet.String() + "/" + meta.Scanner)

		if existing := bkt.Get(key); existing != nil {
			var prev scanMetaJSON
			if err := json.Unmarshal(existing, &prev); err != nil {
				return fmt.Errorf("corrupt scan metadata %q: %w", key, err)
			}
			meta.ErrorCount = prev.ErrorCount
		}
		if meta.Error {
			meta.ErrorCount++
		}

		j := scanMetaJSON{
			Subnet:     meta.Subnet.String(),
			Scanner:    meta.Scanner,
			DurationNS: meta.Duration.Nanoseconds(),
			Timestamp:  meta.Timestamp.UnixNano(),
			Error:      meta.Error,
			ErrorCount: meta.ErrorCount,
		}
		data, err := json.Marshal(j)
		if err != nil {
			return err
		}
		return bkt.Put(key, data)
	})
}

// GetScanMeta returns all scan metadata entries recorded for the given subnet.
// Returns an empty slice (not an error) if no metadata has been recorded yet.
func (b *BoltStore) GetScanMeta(ctx context.Context, subnet netip.Prefix) ([]ScanMeta, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	prefix := subnet.String() + "/"
	result := make([]ScanMeta, 0)
	err := b.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketScanMeta).ForEach(func(k, v []byte) error {
			if err := contextErr(ctx); err != nil {
				return err
			}
			var j scanMetaJSON
			if err := json.Unmarshal(v, &j); err != nil {
				return fmt.Errorf("corrupt scan metadata %q: %w", k, err)
			}
			sub, err := netip.ParsePrefix(j.Subnet)
			if err != nil {
				return fmt.Errorf("corrupt scan metadata %q subnet %q: %w", k, j.Subnet, err)
			}
			key := string(k)
			if key != j.Subnet+"/"+j.Scanner {
				return fmt.Errorf("corrupt scan metadata %q: embedded key is %q", k, j.Subnet+"/"+j.Scanner)
			}
			if len(key) <= len(prefix) || key[:len(prefix)] != prefix {
				return nil
			}
			result = append(result, ScanMeta{
				Subnet:     sub,
				Scanner:    j.Scanner,
				Duration:   time.Duration(j.DurationNS),
				Timestamp:  time.Unix(0, j.Timestamp).UTC(),
				Error:      j.Error,
				ErrorCount: j.ErrorCount,
			})
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
