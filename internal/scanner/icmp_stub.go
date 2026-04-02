//go:build !linux

package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"
)

// ICMPScanner is a no-op stub on non-Linux platforms.
type ICMPScanner struct{}

// NewICMPScanner returns a stub scanner that always errors on Scan.
func NewICMPScanner(_ time.Duration, _ time.Duration, _ *slog.Logger) *ICMPScanner {
	return &ICMPScanner{}
}

// Name returns the scanner identifier.
func (s *ICMPScanner) Name() string { return "icmp" }

// Scan always returns an error on non-Linux platforms.
func (s *ICMPScanner) Scan(_ context.Context, _ netip.Prefix) ([]ScanResult, error) {
	return nil, fmt.Errorf("ICMP scanning is only supported on Linux")
}
