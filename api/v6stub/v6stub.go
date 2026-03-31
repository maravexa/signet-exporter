// Package v6stub defines types and interfaces for future IPv6 NDP (Neighbor
// Discovery Protocol) support. No implementation is provided; this package
// exists to reserve the API surface for a subsequent development phase.
package v6stub

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// NDPEntry represents a single entry from the IPv6 neighbor cache.
type NDPEntry struct {
	IP        netip.Addr
	MAC       net.HardwareAddr
	State     NDPState
	Timestamp time.Time
}

// NDPState describes the reachability state of a neighbor cache entry.
type NDPState string

const (
	NDPStateReachable  NDPState = "REACHABLE"
	NDPStateStale      NDPState = "STALE"
	NDPStateDelay      NDPState = "DELAY"
	NDPStateProbe      NDPState = "PROBE"
	NDPStateIncomplete NDPState = "INCOMPLETE"
	NDPStateFailed     NDPState = "FAILED"
)

// NDPScanner is the interface for future IPv6 neighbor discovery scanning.
type NDPScanner interface {
	// Scan returns NDP neighbor cache entries for the given IPv6 prefix.
	Scan(ctx context.Context, prefix netip.Prefix) ([]NDPEntry, error)
}
