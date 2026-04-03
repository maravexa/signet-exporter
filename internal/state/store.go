// Package state provides types and interfaces for tracking host inventory state.
package state

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// HostChange describes what changed during an UpdateHost call.
// It is returned by value and computed inside the store's write lock.
type HostChange struct {
	IsNew      bool             // true if this IP was not previously in the store
	MACChanged bool             // true if the MAC address changed (implies IsNew == false)
	OldMAC     net.HardwareAddr // previous MAC (nil if IsNew or no change)
	OldVendor  string           // previous vendor (empty if IsNew or no change)
}

// Store defines the interface for persisting and querying host inventory state.
type Store interface {
	// UpdateHost inserts or updates a host record and reports what changed.
	UpdateHost(ctx context.Context, record HostRecord) (HostChange, error)

	// GetHost retrieves a host record by IP address.
	GetHost(ctx context.Context, ip netip.Addr) (*HostRecord, error)

	// ListHosts returns all host records within the given subnet prefix.
	ListHosts(ctx context.Context, subnet netip.Prefix) ([]HostRecord, error)

	// RecordMACChange appends a MAC-IP change event to the audit log.
	RecordMACChange(ctx context.Context, event MACIPChange) error

	// RecentChanges returns all MAC-IP change events since the given time.
	RecentChanges(ctx context.Context, since time.Time) ([]MACIPChange, error)

	// RecordScanMeta stores timing metadata for the most recent scan of a subnet/scanner pair.
	RecordScanMeta(ctx context.Context, meta ScanMeta) error

	// GetScanMeta returns all scan metadata entries for the given subnet.
	// Returns an empty slice (not an error) if no metadata has been recorded yet.
	GetScanMeta(ctx context.Context, subnet netip.Prefix) ([]ScanMeta, error)

	// Close releases any resources held by the store.
	Close() error
}
