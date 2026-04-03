package state

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
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

// BoltStore is a bbolt-backed persistent Store implementation.
//
// Bucket layout:
//
//	"hosts"    → key: IP string     → value: JSON hostRecordJSON
//	"changes"  → key: 8-byte big-endian sequence → value: JSON macIPChangeJSON
//	"scanmeta" → key: "subnet/scanner" → value: JSON scanMetaJSON
//	"meta"     → key: "version"     → value: schema version ("1")
type BoltStore struct {
	db *bolt.DB
}

// NewBoltStore opens or creates the bbolt database at path.
// File mode 0o660 (owner+group rw). Timeout 1s — fail fast if another process
// holds the lock (i.e. another signet-exporter instance is running).
// Creates all required buckets and writes schema version on first open.
func NewBoltStore(path string) (*BoltStore, error) {
	opts := &bolt.Options{Timeout: time.Second}
	db, err := bolt.Open(path, 0o660, opts) //nolint:gosec // G304: path is operator-supplied config, not user input
	if err != nil {
		return nil, fmt.Errorf("open bolt db %q: %w", path, err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketHosts, bucketChanges, bucketScanMeta, bucketMeta} {
			if _, berr := tx.CreateBucketIfNotExists(name); berr != nil {
				return fmt.Errorf("create bucket %q: %w", name, berr)
			}
		}
		meta := tx.Bucket(bucketMeta)
		if meta.Get(keyVersion) == nil {
			return meta.Put(keyVersion, schemaVersion)
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init bolt schema: %w", err)
	}

	return &BoltStore{db: db}, nil
}

// Close closes the underlying bbolt database.
func (b *BoltStore) Close() error {
	return b.db.Close()
}

// ---- JSON wire types -------------------------------------------------------

// hostRecordJSON is the on-disk representation of HostRecord.
// net.HardwareAddr values are stored as colon-separated hex MAC strings.
type hostRecordJSON struct {
	IP                   string   `json:"ip"`
	MAC                  string   `json:"mac,omitempty"`
	Vendor               string   `json:"vendor,omitempty"`
	Hostnames            []string `json:"hostnames,omitempty"`
	DNSMismatches        []string `json:"dns_mismatches,omitempty"`
	FirstSeen            int64    `json:"first_seen_ns"`
	LastSeen             int64    `json:"last_seen_ns"`
	OpenPorts            []uint16 `json:"open_ports,omitempty"`
	DuplicateMACs        []string `json:"duplicate_macs,omitempty"`
	Alive                bool     `json:"alive"`
	Authorized           bool     `json:"authorized"`
	AuthorizationChecked bool     `json:"authorization_checked"`
	DuplicateChecked     bool     `json:"duplicate_checked"`
	MACChangeCount       uint64   `json:"mac_change_count"`
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
		IP:                   r.IP.String(),
		Vendor:               r.Vendor,
		Hostnames:            r.Hostnames,
		DNSMismatches:        r.DNSMismatches,
		FirstSeen:            r.FirstSeen.UnixNano(),
		LastSeen:             r.LastSeen.UnixNano(),
		OpenPorts:            r.OpenPorts,
		Alive:                r.Alive,
		Authorized:           r.Authorized,
		AuthorizationChecked: r.AuthorizationChecked,
		DuplicateChecked:     r.DuplicateChecked,
		MACChangeCount:       r.MACChangeCount,
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
		IP:                   ip,
		Vendor:               j.Vendor,
		Hostnames:            j.Hostnames,
		DNSMismatches:        j.DNSMismatches,
		FirstSeen:            time.Unix(0, j.FirstSeen).UTC(),
		LastSeen:             time.Unix(0, j.LastSeen).UTC(),
		OpenPorts:            j.OpenPorts,
		Alive:                j.Alive,
		Authorized:           j.Authorized,
		AuthorizationChecked: j.AuthorizationChecked,
		DuplicateChecked:     j.DuplicateChecked,
		MACChangeCount:       j.MACChangeCount,
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
	return r, nil
}

// appendChangeTx writes a MACIPChange into the changes bucket using an
// auto-incrementing sequence key. Must be called inside a write transaction.
func appendChangeTx(tx *bolt.Tx, event MACIPChange) error {
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
	return bkt.Put(key[:], data)
}

// ---- Store interface implementation ----------------------------------------

// UpdateHost inserts or updates a host record and reports what changed.
// The entire read-modify-write is performed atomically inside a single db.Update.
func (b *BoltStore) UpdateHost(_ context.Context, record HostRecord) (HostChange, error) {
	var change HostChange
	err := b.db.Update(func(tx *bolt.Tx) error {
		hBkt := tx.Bucket(bucketHosts)
		key := []byte(record.IP.String())
		data := hBkt.Get(key)

		// ---- new host -------------------------------------------------------
		if data == nil {
			r := record
			if r.FirstSeen.IsZero() {
				r.FirstSeen = r.LastSeen
			}
			encoded, err := marshalHostRecord(r)
			if err != nil {
				return err
			}
			change = HostChange{
				IsNew:             true,
				DuplicateDetected: record.DuplicateChecked && len(record.DuplicateMACs) > 0,
			}
			return hBkt.Put(key, encoded)
		}

		existing, err := unmarshalHostRecord(data)
		if err != nil {
			return fmt.Errorf("unmarshal existing host %s: %w", record.IP, err)
		}

		// ---- no MAC in incoming record (ICMP / DNS) -------------------------
		if len(record.MAC) == 0 {
			existing.LastSeen = record.LastSeen
			existing.Alive = record.Alive
			if len(record.Hostnames) > 0 {
				existing.Hostnames = make([]string, len(record.Hostnames))
				copy(existing.Hostnames, record.Hostnames)
			}
			if record.DNSMismatches != nil {
				existing.DNSMismatches = make([]string, len(record.DNSMismatches))
				copy(existing.DNSMismatches, record.DNSMismatches)
			}
			if len(record.OpenPorts) > 0 {
				existing.OpenPorts = make([]uint16, len(record.OpenPorts))
				copy(existing.OpenPorts, record.OpenPorts)
			}
			encoded, err := marshalHostRecord(existing)
			if err != nil {
				return err
			}
			change = HostChange{}
			return hBkt.Put(key, encoded)
		}

		// ---- same MAC -------------------------------------------------------
		if bytes.Equal(existing.MAC, record.MAC) {
			existing.LastSeen = record.LastSeen
			if len(record.Hostnames) > 0 {
				existing.Hostnames = make([]string, len(record.Hostnames))
				copy(existing.Hostnames, record.Hostnames)
			}
			if record.DNSMismatches != nil {
				existing.DNSMismatches = make([]string, len(record.DNSMismatches))
				copy(existing.DNSMismatches, record.DNSMismatches)
			}
			if len(record.OpenPorts) > 0 {
				existing.OpenPorts = make([]uint16, len(record.OpenPorts))
				copy(existing.OpenPorts, record.OpenPorts)
			}
			existing.Vendor = record.Vendor
			if record.AuthorizationChecked {
				existing.AuthorizationChecked = true
				existing.Authorized = record.Authorized
			}
			if record.DuplicateChecked {
				existing.DuplicateChecked = true
				existing.DuplicateMACs = copyDuplicateMACs(record.DuplicateMACs)
			}
			existing.Alive = record.Alive
			encoded, err := marshalHostRecord(existing)
			if err != nil {
				return err
			}
			change = HostChange{DuplicateDetected: record.DuplicateChecked && len(record.DuplicateMACs) > 0}
			return hBkt.Put(key, encoded)
		}

		// ---- MAC changed ----------------------------------------------------
		hostChange := HostChange{
			MACChanged: true,
			OldMAC:     make(net.HardwareAddr, len(existing.MAC)),
			OldVendor:  existing.Vendor,
		}
		copy(hostChange.OldMAC, existing.MAC)

		macIPChange := MACIPChange{
			IP:        record.IP,
			OldMAC:    make(net.HardwareAddr, len(existing.MAC)),
			NewMAC:    make(net.HardwareAddr, len(record.MAC)),
			Timestamp: record.LastSeen,
		}
		copy(macIPChange.OldMAC, existing.MAC)
		copy(macIPChange.NewMAC, record.MAC)
		if err := appendChangeTx(tx, macIPChange); err != nil {
			return err
		}

		existing.MAC = make(net.HardwareAddr, len(record.MAC))
		copy(existing.MAC, record.MAC)
		existing.LastSeen = record.LastSeen
		if len(record.Hostnames) > 0 {
			existing.Hostnames = make([]string, len(record.Hostnames))
			copy(existing.Hostnames, record.Hostnames)
		}
		if record.DNSMismatches != nil {
			existing.DNSMismatches = make([]string, len(record.DNSMismatches))
			copy(existing.DNSMismatches, record.DNSMismatches)
		}
		if len(record.OpenPorts) > 0 {
			existing.OpenPorts = make([]uint16, len(record.OpenPorts))
			copy(existing.OpenPorts, record.OpenPorts)
		}
		existing.Vendor = record.Vendor
		if record.AuthorizationChecked {
			existing.AuthorizationChecked = true
			existing.Authorized = record.Authorized
		}
		if record.DuplicateChecked {
			existing.DuplicateChecked = true
			existing.DuplicateMACs = copyDuplicateMACs(record.DuplicateMACs)
		}
		existing.Alive = record.Alive
		existing.MACChangeCount++
		hostChange.DuplicateDetected = record.DuplicateChecked && len(record.DuplicateMACs) > 0

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
func (b *BoltStore) GetHost(_ context.Context, ip netip.Addr) (*HostRecord, error) {
	var result *HostRecord
	err := b.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketHosts).Get([]byte(ip.String()))
		if data == nil {
			return nil
		}
		r, rerr := unmarshalHostRecord(data)
		if rerr != nil {
			return rerr
		}
		result = &r
		return nil
	})
	return result, err
}

// ListHosts returns all host records within the given subnet prefix.
// If subnet is the zero prefix, all hosts are returned.
// Always returns a non-nil slice.
func (b *BoltStore) ListHosts(_ context.Context, subnet netip.Prefix) ([]HostRecord, error) {
	result := make([]HostRecord, 0)
	zeroPrefix := netip.Prefix{}
	err := b.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketHosts).ForEach(func(k, v []byte) error {
			if subnet != zeroPrefix {
				ip, perr := netip.ParseAddr(string(k))
				if perr != nil || !subnet.Contains(ip) {
					return nil
				}
			}
			r, rerr := unmarshalHostRecord(v)
			if rerr != nil {
				return nil // skip corrupt records
			}
			result = append(result, r)
			return nil
		})
	})
	return result, err
}

// RecordMACChange appends a MAC-IP change event to persistent storage.
func (b *BoltStore) RecordMACChange(_ context.Context, event MACIPChange) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		return appendChangeTx(tx, event)
	})
}

// RecentChanges returns all MAC-IP change events at or after the given time.
func (b *BoltStore) RecentChanges(_ context.Context, since time.Time) ([]MACIPChange, error) {
	sinceNS := since.UnixNano()
	result := make([]MACIPChange, 0)
	err := b.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketChanges).ForEach(func(_, v []byte) error {
			var j macIPChangeJSON
			if err := json.Unmarshal(v, &j); err != nil {
				return nil // skip corrupt entries
			}
			if j.Timestamp < sinceNS {
				return nil
			}
			ip, err := netip.ParseAddr(j.IP)
			if err != nil {
				return nil
			}
			oldMAC, err := net.ParseMAC(j.OldMAC)
			if err != nil {
				return nil
			}
			newMAC, err := net.ParseMAC(j.NewMAC)
			if err != nil {
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
	return result, err
}

// RecordScanMeta stores timing metadata for a subnet/scanner pair.
// ErrorCount is a cumulative monotonic counter: preserved across updates,
// incremented when meta.Error is true — matching MemoryStore semantics.
func (b *BoltStore) RecordScanMeta(_ context.Context, meta ScanMeta) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bucketScanMeta)
		key := []byte(meta.Subnet.String() + "/" + meta.Scanner)

		if existing := bkt.Get(key); existing != nil {
			var prev scanMetaJSON
			if err := json.Unmarshal(existing, &prev); err == nil {
				meta.ErrorCount = prev.ErrorCount
			}
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
func (b *BoltStore) GetScanMeta(_ context.Context, subnet netip.Prefix) ([]ScanMeta, error) {
	prefix := subnet.String() + "/"
	result := make([]ScanMeta, 0)
	err := b.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketScanMeta).ForEach(func(k, v []byte) error {
			key := string(k)
			if len(key) <= len(prefix) || key[:len(prefix)] != prefix {
				return nil
			}
			var j scanMetaJSON
			if err := json.Unmarshal(v, &j); err != nil {
				return nil
			}
			sub, err := netip.ParsePrefix(j.Subnet)
			if err != nil {
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
	return result, err
}
