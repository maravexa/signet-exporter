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

// UpdateHost inserts or updates a host record.
func (m *MemoryStore) UpdateHost(_ context.Context, record HostRecord) error {
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
		macKey := record.MAC.String()
		m.macIndex[macKey] = append(m.macIndex[macKey], record.IP)
		return nil
	}

	if bytes.Equal(existing.MAC, record.MAC) {
		// Same MAC — update fields, preserve FirstSeen
		existing.LastSeen = record.LastSeen
		existing.Hostnames = make([]string, len(record.Hostnames))
		copy(existing.Hostnames, record.Hostnames)
		existing.OpenPorts = make([]uint16, len(record.OpenPorts))
		copy(existing.OpenPorts, record.OpenPorts)
		existing.Vendor = record.Vendor
		existing.Authorized = record.Authorized
		existing.Alive = record.Alive
		return nil
	}

	// Different MAC — binding change
	change := MACIPChange{
		IP:        record.IP,
		OldMAC:    make(net.HardwareAddr, len(existing.MAC)),
		NewMAC:    make(net.HardwareAddr, len(record.MAC)),
		Timestamp: record.LastSeen,
	}
	copy(change.OldMAC, existing.MAC)
	copy(change.NewMAC, record.MAC)
	m.appendChange(change)

	// Update macIndex: remove IP from old MAC, add to new MAC
	oldKey := existing.MAC.String()
	newKey := record.MAC.String()
	m.macIndex[oldKey] = removeAddr(m.macIndex[oldKey], record.IP)
	m.macIndex[newKey] = append(m.macIndex[newKey], record.IP)

	// Update the record
	existing.MAC = make(net.HardwareAddr, len(record.MAC))
	copy(existing.MAC, record.MAC)
	existing.LastSeen = record.LastSeen
	existing.Hostnames = make([]string, len(record.Hostnames))
	copy(existing.Hostnames, record.Hostnames)
	existing.OpenPorts = make([]uint16, len(record.OpenPorts))
	copy(existing.OpenPorts, record.OpenPorts)
	existing.Vendor = record.Vendor
	existing.Authorized = record.Authorized
	existing.Alive = record.Alive

	return nil
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
