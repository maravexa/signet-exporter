package state

import (
	"context"
	"fmt"
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

// WithMaxChanges sets the finite ring-buffer capacity for MAC-IP change events.
// Non-positive values fall back to DefaultMaxChanges.
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
		maxChanges: DefaultMaxChanges,
		scanMeta:   make(map[string]ScanMeta),
	}
	for _, opt := range opts {
		opt(m)
	}
	if m.maxChanges <= 0 {
		m.maxChanges = DefaultMaxChanges
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

	if r.DuplicateMACs != nil {
		out.DuplicateMACs = make([]net.HardwareAddr, len(r.DuplicateMACs))
		for i, mac := range r.DuplicateMACs {
			dupMAC := make(net.HardwareAddr, len(mac))
			copy(dupMAC, mac)
			out.DuplicateMACs[i] = dupMAC
		}
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
func (m *MemoryStore) UpdateHost(ctx context.Context, record HostRecord) (HostChange, error) {
	if err := contextErr(ctx); err != nil {
		return HostChange{}, err
	}
	if !validObservationSource(record.Source) {
		return HostChange{}, fmt.Errorf("unknown observation source %q", record.Source)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.hosts[record.IP]
	if !ok {
		if !sourceCanCreateHost(record.Source) {
			// Enrichment results are derived from a prior state snapshot. They must
			// not recreate a host that TTL eviction (or another writer) removed.
			return HostChange{}, nil
		}
		r := newObservedHost(record)
		m.hosts[record.IP] = &r
		if len(r.MAC) > 0 {
			macKey := r.MAC.String()
			m.macIndex[macKey] = append(m.macIndex[macKey], record.IP)
		}
		return HostChange{
			Applied:           true,
			IsNew:             true,
			DuplicateDetected: record.DuplicateChecked && len(record.DuplicateMACs) > 0,
		}, nil
	}

	oldMAC := append(net.HardwareAddr(nil), existing.MAC...)
	change, macChange, applied := applyHostObservation(existing, record)
	if !applied {
		return change, nil
	}
	change.Applied = true
	if oldMAC.String() != existing.MAC.String() {
		if len(oldMAC) > 0 {
			oldKey := oldMAC.String()
			m.macIndex[oldKey] = removeAddr(m.macIndex[oldKey], record.IP)
			if len(m.macIndex[oldKey]) == 0 {
				delete(m.macIndex, oldKey)
			}
		}
		if len(existing.MAC) > 0 {
			newKey := existing.MAC.String()
			m.macIndex[newKey] = append(m.macIndex[newKey], record.IP)
		}
	}
	if macChange != nil {
		m.appendChange(*macChange)
	}
	return change, nil
}

// copyDuplicateMACs returns a deep copy of a []net.HardwareAddr slice.
// Returns nil when the input is nil (preserves nil semantics).
func copyDuplicateMACs(macs []net.HardwareAddr) []net.HardwareAddr {
	if macs == nil {
		return nil
	}
	out := make([]net.HardwareAddr, len(macs))
	for i, mac := range macs {
		dupMAC := make(net.HardwareAddr, len(mac))
		copy(dupMAC, mac)
		out[i] = dupMAC
	}
	return out
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
func (m *MemoryStore) GetHost(ctx context.Context, ip netip.Addr) (*HostRecord, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
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
func (m *MemoryStore) ListHosts(ctx context.Context, subnet netip.Prefix) ([]HostRecord, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]HostRecord, 0)
	zeroPrefix := netip.Prefix{}
	for ip, record := range m.hosts {
		if err := contextErr(ctx); err != nil {
			return nil, err
		}
		if subnet == zeroPrefix || subnet.Contains(ip) {
			result = append(result, copyHostRecord(record))
		}
	}
	return result, nil
}

// RecordMACChange appends a MAC-IP change event to the audit log.
func (m *MemoryStore) RecordMACChange(ctx context.Context, event MACIPChange) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.appendChange(copyMACIPChange(event))
	return nil
}

// RecentChanges returns all MAC-IP change events at or after the given time.
func (m *MemoryStore) RecentChanges(ctx context.Context, since time.Time) ([]MACIPChange, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]MACIPChange, 0)
	for _, c := range m.changes {
		if err := contextErr(ctx); err != nil {
			return nil, err
		}
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
func (m *MemoryStore) RecordScanMeta(ctx context.Context, meta ScanMeta) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
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
func (m *MemoryStore) GetScanMeta(ctx context.Context, subnet netip.Prefix) ([]ScanMeta, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	prefix := subnet.String() + "/"
	result := make([]ScanMeta, 0)
	for key, meta := range m.scanMeta {
		if err := contextErr(ctx); err != nil {
			return nil, err
		}
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			result = append(result, meta)
		}
	}
	return result, nil
}

// PruneStale removes all hosts whose LastSeen is older than ttl.
// Returns the IPs of removed hosts. Holds the write lock for the full sweep to
// prevent races with concurrent UpdateHost calls.
func (m *MemoryStore) PruneStale(ttl time.Duration) ([]string, error) {
	removedHosts, err := m.PruneStaleHosts(ttl)
	if err != nil {
		return nil, err
	}
	removed := make([]string, len(removedHosts))
	for i, host := range removedHosts {
		removed[i] = host.IP.String()
	}
	return removed, nil
}

// PruneStaleHosts removes stale hosts and returns deep copies of their state
// immediately before deletion. The sweep and deletion occur under one write
// lock, so returned records are suitable for accurate expiry audit events.
func (m *MemoryStore) PruneStaleHosts(ttl time.Duration) ([]HostRecord, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("invalid TTL: %v", ttl)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	removed := make([]HostRecord, 0)
	for ip, host := range m.hosts {
		if IsStale(host.LastSeen, ttl) {
			removed = append(removed, copyHostRecord(host))
			// Clean up macIndex for this host.
			if len(host.MAC) > 0 {
				macKey := host.MAC.String()
				m.macIndex[macKey] = removeAddr(m.macIndex[macKey], ip)
				if len(m.macIndex[macKey]) == 0 {
					delete(m.macIndex, macKey)
				}
			}
			delete(m.hosts, ip)
		}
	}
	return removed, nil
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
