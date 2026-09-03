// Package scanner defines the Scanner interface and types used by all probe implementations.
package scanner

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// maxDuplicateMACsPerIP bounds retained ARP conflict evidence per address.
// It is defined outside the Linux ARP implementation so runtime reporting
// remains portable.
const maxDuplicateMACsPerIP = 16

// maxDNSNamesPerHost bounds DNS-derived labels and mismatch evidence per host.
const maxDNSNamesPerHost = 32

// Scanner is the interface that all network probe implementations must satisfy.
type Scanner interface {
	// Name returns a short identifier for the scanner (e.g., "arp", "icmp").
	Name() string

	// Scan probes all addresses in the given subnet prefix and returns results.
	Scan(ctx context.Context, subnet netip.Prefix) ([]ScanResult, error)
}

// ScanResult holds the outcome of probing a single IP address.
type ScanResult struct {
	IP               netip.Addr
	MAC              net.HardwareAddr
	Alive            bool
	Source           string // "arp", "icmp", "port", "dns"
	Timestamp        time.Time
	Metadata         map[string]string
	Hostnames        []string           // populated by the DNS scanner
	DNSMismatches    []string           // hostnames where forward lookup didn't resolve back to this IP
	OpenPorts        []uint16           // populated by the port scanner
	DuplicateMACs    []net.HardwareAddr // other MACs that also claimed this IP in the same ARP window
	DuplicateChecked bool               // true if the ARP scanner authoratively set DuplicateMACs for this result
}
