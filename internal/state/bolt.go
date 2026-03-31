package state

import (
	"context"
	"net/netip"
	"time"

	bolt "go.etcd.io/bbolt"
)

// BoltStore is a bbolt-backed persistent StateStore implementation.
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

func (b *BoltStore) UpdateHost(_ context.Context, _ HostRecord) error {
	// TODO: implement bbolt-backed host record persistence
	return nil
}

func (b *BoltStore) GetHost(_ context.Context, _ netip.Addr) (*HostRecord, error) {
	// TODO: implement bbolt-backed host lookup
	return nil, nil
}

func (b *BoltStore) ListHosts(_ context.Context, _ netip.Prefix) ([]HostRecord, error) {
	// TODO: implement bbolt-backed subnet listing
	return nil, nil
}

func (b *BoltStore) RecordMACChange(_ context.Context, _ MACIPChange) error {
	// TODO: implement bbolt-backed MAC change event recording
	return nil
}

func (b *BoltStore) RecentChanges(_ context.Context, _ time.Time) ([]MACIPChange, error) {
	// TODO: implement bbolt-backed recent changes query
	return nil, nil
}

func (b *BoltStore) Close() error {
	return b.db.Close()
}
