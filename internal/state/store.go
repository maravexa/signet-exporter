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
	Applied           bool             // true only when this observation was committed
	IsNew             bool             // true if this IP was not previously in the store
	MACChanged        bool             // true if the MAC address changed (implies IsNew == false)
	OldMAC            net.HardwareAddr // previous MAC (nil if IsNew or no change)
	OldVendor         string           // previous vendor (empty if IsNew or no change)
	DuplicateDetected bool             // true if ARP found multiple MACs claiming this IP
}

// Store defines the interface for persisting and querying host inventory state.
type Store interface {
	// UpdateHost inserts or applies a source-owned observation and reports what
	// changed. New callers must set record.Source and record.ObservedAt. Each
	// source can mutate only its documented fields in HostRecord; a delayed
	// observation older than that source's persisted watermark is ignored.
	//
	// ARP and ICMP are the only sources that establish or refresh host
	// liveness. DNS, port, and authorization observations enrich an existing
	// host and cannot recreate one that TTL eviction removed. A non-nil empty
	// source-owned slice is an explicit successful-empty observation and clears
	// that field. The empty Source retains the pre-source legacy behavior for
	// compatibility and should not be used by scanner/runtime code.
	UpdateHost(ctx context.Context, record HostRecord) (HostChange, error)

	// GetHost retrieves a host record by IP address.
	GetHost(ctx context.Context, ip netip.Addr) (*HostRecord, error)

	// ListHosts returns all host records within the given subnet prefix.
	ListHosts(ctx context.Context, subnet netip.Prefix) ([]HostRecord, error)

	// RecordMACChange appends a MAC-IP change event to the audit log.
	RecordMACChange(ctx context.Context, event MACIPChange) error

	// RecentChanges returns retained MAC-IP change events since the given time.
	// History is finite (DefaultMaxChanges by default) in both backends.
	RecentChanges(ctx context.Context, since time.Time) ([]MACIPChange, error)

	// RecordScanMeta stores timing metadata for the most recent scan of a subnet/scanner pair.
	RecordScanMeta(ctx context.Context, meta ScanMeta) error

	// GetScanMeta returns all scan metadata entries for the given subnet.
	// Returns an empty slice (not an error) if no metadata has been recorded yet.
	GetScanMeta(ctx context.Context, subnet netip.Prefix) ([]ScanMeta, error)

	// PruneStale removes hosts not seen within ttl. Returns the list of removed
	// host IPs so the caller can emit audit events. The state store does not
	// emit audit events itself — callers decide what to do with removed hosts.
	// Returns an error if ttl is zero or negative, or if the underlying store fails.
	PruneStale(ttl time.Duration) ([]string, error)

	// PruneStaleHosts removes hosts not seen within ttl and returns deep-copied
	// records from immediately before deletion. It is atomic with the deletion,
	// so callers can accurately audit the expired binding without a race against
	// a concurrent rediscovery. PruneStale remains available for IP-only callers.
	PruneStaleHosts(ttl time.Duration) ([]HostRecord, error)

	// Close releases any resources held by the store.
	Close() error
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
