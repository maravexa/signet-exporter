package scanner

import (
	"context"
	"net/netip"
	"time"
)

// PortScanner performs lightweight TCP connect probes on a configured set of ports.
type PortScanner struct {
	ports   []uint16
	timeout time.Duration
}

// NewPortScanner creates a new port scanner for the given ports and per-probe timeout.
func NewPortScanner(ports []uint16, timeout time.Duration) *PortScanner {
	return &PortScanner{ports: ports, timeout: timeout}
}

// Name returns the scanner identifier.
func (p *PortScanner) Name() string { return "port" }

// Scan attempts TCP connections to each configured port on each address in subnet.
func (p *PortScanner) Scan(_ context.Context, _ netip.Prefix) ([]ScanResult, error) {
	// TODO: implement TCP connect scan with configurable per-port timeout
	return nil, nil
}
