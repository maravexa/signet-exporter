package state

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// MemoryStore is a non-persistent, in-memory StateStore implementation.
type MemoryStore struct {
	mu      sync.RWMutex
	hosts   map[netip.Addr]HostRecord
	changes []MACIPChange
}

// NewMemoryStore creates a new in-memory StateStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		hosts:   make(map[netip.Addr]HostRecord),
		changes: make([]MACIPChange, 0),
	}
}

func (m *MemoryStore) UpdateHost(_ context.Context, record HostRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hosts[record.IP] = record
	return nil
}

func (m *MemoryStore) GetHost(_ context.Context, ip netip.Addr) (*HostRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.hosts[ip]
	if !ok {
		return nil, fmt.Errorf("host %s not found", ip)
	}
	copy := r
	return &copy, nil
}

func (m *MemoryStore) ListHosts(_ context.Context, subnet netip.Prefix) ([]HostRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []HostRecord
	for ip, record := range m.hosts {
		if subnet.Contains(ip) {
			result = append(result, record)
		}
	}
	return result, nil
}

func (m *MemoryStore) RecordMACChange(_ context.Context, event MACIPChange) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.changes = append(m.changes, event)
	return nil
}

func (m *MemoryStore) RecentChanges(_ context.Context, since time.Time) ([]MACIPChange, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []MACIPChange
	for _, c := range m.changes {
		if !c.Timestamp.Before(since) {
			result = append(result, c)
		}
	}
	return result, nil
}

func (m *MemoryStore) Close() error {
	return nil
}
