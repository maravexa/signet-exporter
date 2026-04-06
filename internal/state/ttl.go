package state

import "time"

// IsStale returns true if the host has not been seen within the given TTL.
// LastSeen must already be set on the HostRecord struct (set by UpdateHost on every scan).
func IsStale(lastSeen time.Time, ttl time.Duration) bool {
	return time.Since(lastSeen) > ttl
}
