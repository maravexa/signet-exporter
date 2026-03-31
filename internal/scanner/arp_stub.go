//go:build !linux

package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"
)

// ARPScanner is a no-op stub on non-Linux platforms.
// ARP scanning via AF_PACKET is Linux-only; use Linux for production deployments.
type ARPScanner struct{}

// NewARPScanner returns a stub ARPScanner that always errors.
func NewARPScanner(timeout time.Duration, rateLimit time.Duration, logger *slog.Logger) *ARPScanner {
	return &ARPScanner{}
}

// Name returns the scanner identifier.
func (a *ARPScanner) Name() string { return "arp" }

// Scan always returns an error on non-Linux platforms.
func (a *ARPScanner) Scan(ctx context.Context, subnet netip.Prefix) ([]ScanResult, error) {
	return nil, fmt.Errorf("ARP scanning is only supported on Linux (requires AF_PACKET)")
}
