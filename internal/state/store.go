package state

import (
	"context"
	"net/netip"
	"time"
)

// StateStore defines the interface for persisting and querying host inventory state.
type StateStore interface {
	// UpdateHost inserts or updates a host record.
	UpdateHost(ctx context.Context, record HostRecord) error

	// GetHost retrieves a host record by IP address.
	GetHost(ctx context.Context, ip netip.Addr) (*HostRecord, error)

	// ListHosts returns all host records within the given subnet prefix.
	ListHosts(ctx context.Context, subnet netip.Prefix) ([]HostRecord, error)

	// RecordMACChange appends a MAC-IP change event to the audit log.
	RecordMACChange(ctx context.Context, event MACIPChange) error

	// RecentChanges returns all MAC-IP change events since the given time.
	RecentChanges(ctx context.Context, since time.Time) ([]MACIPChange, error)

	// Close releases any resources held by the store.
	Close() error
}
