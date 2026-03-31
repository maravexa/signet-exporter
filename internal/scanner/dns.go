package scanner

import (
	"context"
	"net/netip"
	"time"
)

// DNSScanner performs forward and reverse DNS lookups to detect mismatches.
type DNSScanner struct {
	servers []string
	timeout time.Duration
}

// NewDNSScanner creates a new DNS scanner using the given resolver addresses and timeout.
func NewDNSScanner(servers []string, timeout time.Duration) *DNSScanner {
	return &DNSScanner{servers: servers, timeout: timeout}
}

// Name returns the scanner identifier.
func (d *DNSScanner) Name() string { return "dns" }

// Scan performs forward/reverse DNS consistency checks for hosts in subnet.
func (d *DNSScanner) Scan(_ context.Context, _ netip.Prefix) ([]ScanResult, error) {
	// TODO: implement forward/reverse DNS mismatch detection
	return nil, nil
}
