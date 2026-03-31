package state

import (
	"context"
	"net/netip"
	"time"

	bolt "go.etcd.io/bbolt"
)

// BoltStore is a bbolt-backed persistent Store implementation.
type BoltStore struct {
	db *bolt.DB
}

// NewBoltStore opens (or creates) a bbolt database at the given path.
func NewBoltStore(path string) (*BoltStore, error) {
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, err
	}
	return &BoltStore{db: db}, nil
}

// UpdateHost inserts or updates a host record.
func (b *BoltStore) UpdateHost(_ context.Context, _ HostRecord) error {
	// TODO: implement bbolt-backed host record persistence
	return nil
}

// GetHost retrieves a host record by IP address.
func (b *BoltStore) GetHost(_ context.Context, _ netip.Addr) (*HostRecord, error) {
	// TODO: implement bbolt-backed host lookup
	return nil, nil
}

// ListHosts returns all host records within the given subnet prefix.
func (b *BoltStore) ListHosts(_ context.Context, _ netip.Prefix) ([]HostRecord, error) {
	// TODO: implement bbolt-backed subnet listing
	return nil, nil
}

// RecordMACChange appends a MAC-IP change event to the audit log.
func (b *BoltStore) RecordMACChange(_ context.Context, _ MACIPChange) error {
	// TODO: implement bbolt-backed MAC change event recording
	return nil
}

// RecentChanges returns all MAC-IP change events since the given time.
func (b *BoltStore) RecentChanges(_ context.Context, _ time.Time) ([]MACIPChange, error) {
	// TODO: implement bbolt-backed recent changes query
	return nil, nil
}

// RecordScanMeta is not yet implemented for the bbolt backend.
func (b *BoltStore) RecordScanMeta(_ context.Context, _ ScanMeta) error {
	// TODO: implement bbolt-backed scan metadata persistence
	return nil
}

// GetScanMeta is not yet implemented for the bbolt backend.
func (b *BoltStore) GetScanMeta(_ context.Context, _ netip.Prefix) ([]ScanMeta, error) {
	// TODO: implement bbolt-backed scan metadata retrieval
	return []ScanMeta{}, nil
}

// Close closes the underlying bbolt database.
func (b *BoltStore) Close() error {
	return b.db.Close()
}
