// Package scanner defines the Scanner interface and types used by all probe implementations.
package scanner

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// Scanner is the interface that all network probe implementations must satisfy.
type Scanner interface {
	// Name returns a short identifier for the scanner (e.g., "arp", "icmp").
	Name() string

	// Scan probes all addresses in the given subnet prefix and returns results.
	Scan(ctx context.Context, subnet netip.Prefix) ([]ScanResult, error)
}

// ScanResult holds the outcome of probing a single IP address.
type ScanResult struct {
	IP            netip.Addr
	MAC           net.HardwareAddr
	Alive         bool
	Source        string // "arp", "icmp", "port", "dns"
	Timestamp     time.Time
	Metadata      map[string]string
	Hostnames     []string // populated by the DNS scanner
	DNSMismatches []string // hostnames where forward lookup didn't resolve back to this IP
	OpenPorts     []uint16 // populated by the port scanner
}
