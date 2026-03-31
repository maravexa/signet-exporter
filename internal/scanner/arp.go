package scanner

import (
	"context"
	"net/netip"
	"time"
)

// ARPScanner performs ARP sweep probes to discover live hosts and MAC addresses.
type ARPScanner struct {
	timeout time.Duration
}

// NewARPScanner creates a new ARP scanner with the given per-probe timeout.
func NewARPScanner(timeout time.Duration) *ARPScanner {
	return &ARPScanner{timeout: timeout}
}

// Name returns the scanner identifier.
func (a *ARPScanner) Name() string { return "arp" }

// Scan broadcasts ARP requests for every address in subnet and returns responses.
func (a *ARPScanner) Scan(_ context.Context, _ netip.Prefix) ([]ScanResult, error) {
	// TODO: implement ARP sweep using raw sockets (requires CAP_NET_RAW)
	return nil, nil
}
