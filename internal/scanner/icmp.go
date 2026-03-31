package scanner

import (
	"context"
	"net/netip"
	"time"
)

// ICMPScanner performs ICMP echo-request probes to check host reachability.
type ICMPScanner struct {
	timeout time.Duration
}

// NewICMPScanner creates a new ICMP scanner with the given per-probe timeout.
func NewICMPScanner(timeout time.Duration) *ICMPScanner {
	return &ICMPScanner{timeout: timeout}
}

// Name returns the scanner identifier.
func (i *ICMPScanner) Name() string { return "icmp" }

// Scan sends ICMP echo requests to each address in subnet and records liveness.
func (i *ICMPScanner) Scan(_ context.Context, _ netip.Prefix) ([]ScanResult, error) {
	// TODO: implement ICMP probe using golang.org/x/net/icmp (requires CAP_NET_RAW)
	return nil, nil
}
