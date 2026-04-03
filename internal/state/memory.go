package state

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

// MemoryStore is a non-persistent, in-memory Store implementation.
type MemoryStore struct {
	mu         sync.RWMutex
	hosts      map[netip.Addr]*HostRecord // primary index: IP → record
	macIndex   map[string][]netip.Addr    // reverse index: MAC string → IPs
	changes    []MACIPChange              // append-only ring buffer of MAC-IP binding changes
	maxChanges int                        // ring buffer capacity
	scanMeta   map[string]ScanMeta        // key: subnet.String() + "/" + scanner
}

// MemoryStoreOption is a functional option for MemoryStore.
type MemoryStoreOption func(*MemoryStore)

// WithMaxChanges sets the ring buffer capacity for MAC-IP change events.
func WithMaxChanges(n int) MemoryStoreOption {
	return func(m *MemoryStore) {
		m.maxChanges = n
	}
}

// NewMemoryStore creates a new in-memory Store with optional configuration.
func NewMemoryStore(opts ...MemoryStoreOption) *MemoryStore {
	m := &MemoryStore{
		hosts:      make(map[netip.Addr]*HostRecord),
		macIndex:   make(map[string][]netip.Addr),
		changes:    make([]MACIPChange, 0),
		maxChanges: 10000,
		scanMeta:   make(map[string]ScanMeta),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// copyHostRecord returns a deep copy of a HostRecord, duplicating all slice fields.
func copyHostRecord(r *HostRecord) HostRecord {
	out := *r

	if r.MAC != nil {
		out.MAC = make(net.HardwareAddr, len(r.MAC))
		copy(out.MAC, r.MAC)
	}

	if r.Hostnames != nil {
		out.Hostnames = make([]string, len(r.Hostnames))
		copy(out.Hostnames, r.Hostnames)
	}

	if r.DNSMismatches != nil {
		out.DNSMismatches = make([]string, len(r.DNSMismatches))
		copy(out.DNSMismatches, r.DNSMismatches)
	}

	if r.OpenPorts != nil {
		out.OpenPorts = make([]uint16, len(r.OpenPorts))
		copy(out.OpenPorts, r.OpenPorts)
	}

	return out
}

// copyMACIPChange returns a deep copy of a MACIPChange.
func copyMACIPChange(c MACIPChange) MACIPChange {
	out := c
	if c.OldMAC != nil {
		out.OldMAC = make(net.HardwareAddr, len(c.OldMAC))
		copy(out.OldMAC, c.OldMAC)
	}
	if c.NewMAC != nil {
		out.NewMAC = make(net.HardwareAddr, len(c.NewMAC))
		copy(out.NewMAC, c.NewMAC)
	}
	return out
}

// UpdateHost inserts or updates a host record and reports what changed.
// If record.MAC is nil or empty (e.g. from an ICMP scan that has no L2 info),
// the method updates liveness fields but preserves any existing MAC binding.
func (m *MemoryStore) UpdateHost(_ context.Context, record HostRecord) (HostChange, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.hosts[record.IP]
	if !ok {
		// New host
		r := copyHostRecord(&record)
		if r.FirstSeen.IsZero() {
			r.FirstSeen = r.LastSeen
		}
		m.hosts[record.IP] = &r
		// Only index by MAC when one is present; ICMP results have no MAC.
		if len(record.MAC) > 0 {
			macKey := record.MAC.String()
			m.macIndex[macKey] = append(m.macIndex[macKey], record.IP)
		}
		return HostChange{IsNew: true}, nil
	}

	if len(record.MAC) == 0 {
		// No MAC in incoming record (e.g. ICMP or DNS result) — update liveness
		// and enrichment fields but preserve the existing MAC binding.
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
		return HostChange{}, nil
	}

	if bytes.Equal(existing.MAC, record.MAC) {
		// Same MAC — update fields, preserve FirstSeen.
		existing.LastSeen = record.LastSeen
		// Only overwrite Hostnames if the incoming record carries them; an ARP or
		// ICMP result with no hostname data should not clear DNS-populated names.
		if len(record.Hostnames) > 0 {
			existing.Hostnames = make([]string, len(record.Hostnames))
			copy(existing.Hostnames, record.Hostnames)
		}
		// nil means "not checked"; empty slice means "checked, no mismatches".
		if record.DNSMismatches != nil {
			existing.DNSMismatches = make([]string, len(record.DNSMismatches))
			copy(existing.DNSMismatches, record.DNSMismatches)
		}
		if len(record.OpenPorts) > 0 {
			existing.OpenPorts = make([]uint16, len(record.OpenPorts))
			copy(existing.OpenPorts, record.OpenPorts)
		}
		existing.Vendor = record.Vendor
		existing.Authorized = record.Authorized
		existing.Alive = record.Alive
		return HostChange{}, nil
	}

	// Different MAC — binding change. Capture previous state before overwriting.
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
	m.appendChange(macIPChange)

	// Update macIndex: remove IP from old MAC, add to new MAC
	oldKey := existing.MAC.String()
	newKey := record.MAC.String()
	m.macIndex[oldKey] = removeAddr(m.macIndex[oldKey], record.IP)
	m.macIndex[newKey] = append(m.macIndex[newKey], record.IP)

	// Update the record
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
	existing.Authorized = record.Authorized
	existing.Alive = record.Alive
	existing.MACChangeCount++

	return hostChange, nil
}

// appendChange appends to the ring buffer under an already-held write lock.
func (m *MemoryStore) appendChange(c MACIPChange) {
	if len(m.changes) >= m.maxChanges {
		m.changes = append(m.changes[1:], c)
	} else {
		m.changes = append(m.changes, c)
	}
}

// removeAddr returns a new slice with addr removed.
func removeAddr(addrs []netip.Addr, addr netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if a != addr {
			out = append(out, a)
		}
	}
	return out
}

// GetHost retrieves a host record by IP address.
// Returns nil, nil if the host is not found.
func (m *MemoryStore) GetHost(_ context.Context, ip netip.Addr) (*HostRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	r, ok := m.hosts[ip]
	if !ok {
		return nil, nil
	}
	cp := copyHostRecord(r)
	return &cp, nil
}

// ListHosts returns all host records within the given subnet prefix.
// If subnet is the zero prefix, all hosts are returned.
// Always returns a non-nil slice.
func (m *MemoryStore) ListHosts(_ context.Context, subnet netip.Prefix) ([]HostRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]HostRecord, 0)
	zeroPrefix := netip.Prefix{}
	for ip, record := range m.hosts {
		if subnet == zeroPrefix || subnet.Contains(ip) {
			result = append(result, copyHostRecord(record))
		}
	}
	return result, nil
}

// RecordMACChange appends a MAC-IP change event to the audit log.
func (m *MemoryStore) RecordMACChange(_ context.Context, event MACIPChange) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.appendChange(copyMACIPChange(event))
	return nil
}

// RecentChanges returns all MAC-IP change events at or after the given time.
func (m *MemoryStore) RecentChanges(_ context.Context, since time.Time) ([]MACIPChange, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]MACIPChange, 0)
	for _, c := range m.changes {
		if !c.Timestamp.Before(since) {
			result = append(result, copyMACIPChange(c))
		}
	}
	return result, nil
}

// Close is a no-op for the in-memory store.
func (m *MemoryStore) Close() error {
	return nil
}

// RecordScanMeta stores timing metadata for a subnet/scanner pair.
// ErrorCount is maintained as a cumulative monotonic counter: it is preserved
// across updates and incremented when meta.Error is true.
func (m *MemoryStore) RecordScanMeta(_ context.Context, meta ScanMeta) error {
	key := meta.Subnet.String() + "/" + meta.Scanner
	m.mu.Lock()
	defer m.mu.Unlock()

	// Preserve and optionally increment the cumulative error count.
	if existing, ok := m.scanMeta[key]; ok {
		meta.ErrorCount = existing.ErrorCount
	}
	if meta.Error {
		meta.ErrorCount++
	}

	m.scanMeta[key] = meta
	return nil
}

// GetScanMeta returns all scan metadata entries recorded for the given subnet.
// Returns an empty slice (not an error) if no metadata has been recorded yet.
func (m *MemoryStore) GetScanMeta(_ context.Context, subnet netip.Prefix) ([]ScanMeta, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	prefix := subnet.String() + "/"
	result := make([]ScanMeta, 0)
	for key, meta := range m.scanMeta {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			result = append(result, meta)
		}
	}
	return result, nil
}

// HostCount returns the total number of tracked hosts.
func (m *MemoryStore) HostCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.hosts)
}

// SubnetUtilization returns (used, total) for a given prefix.
// "total" is the number of usable addresses: 1 for /32, 2 for /31, 2^host_bits-2 otherwise (IPv4).
// For IPv6, total is 2^host_bits, capped at math.MaxUint64.
// "used" is the count of hosts in the store within that prefix.
func (m *MemoryStore) SubnetUtilization(subnet netip.Prefix) (used int, total uint64) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for ip := range m.hosts {
		if subnet.Contains(ip) {
			used++
		}
	}

	bits := subnet.Bits()
	addr := subnet.Addr()

	if addr.Is4() || addr.Is4In6() {
		hostBits := 32 - bits
		switch hostBits {
		case 0: // /32
			total = 1
		case 1: // /31
			total = 2
		default:
			total = (uint64(1) << hostBits) - 2
		}
	} else {
		// IPv6
		hostBits := 128 - bits
		if hostBits >= 64 {
			total = ^uint64(0) // MaxUint64 — subnet is too large to count
		} else {
			total = uint64(1) << hostBits
		}
	}

	return used, total
}

// IPsForMAC returns all IPs currently associated with a MAC address.
func (m *MemoryStore) IPsForMAC(mac net.HardwareAddr) []netip.Addr {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := mac.String()
	addrs := m.macIndex[key]
	if len(addrs) == 0 {
		return []netip.Addr{}
	}
	out := make([]netip.Addr, len(addrs))
	copy(out, addrs)
	return out
}
