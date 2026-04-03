// Package audit provides a structured JSON audit logger for security-relevant events.
package audit

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"
)

// EventType identifies the kind of audit event.
type EventType string

// Audit event type constants.
const (
	EventMACIPChange        EventType = "mac_ip_change"
	EventNewHost            EventType = "new_host_discovered"
	EventHostDisappeared    EventType = "host_disappeared"
	EventUnauthorizedDevice EventType = "unauthorized_device"
	EventScanCycleComplete  EventType = "scan_cycle_complete"
	EventDuplicateIP        EventType = "duplicate_ip_detected"
)

// Logger emits structured audit events as one JSON object per line.
// It is safe for concurrent use; the underlying slog.Logger handles synchronization.
type Logger struct {
	slog    *slog.Logger
	closeFn func() error // non-nil only when we opened a file
}

// Config holds audit logger configuration.
type Config struct {
	Enabled bool
	Output  string // "stderr" or a file path
}

// NewLogger creates an audit logger based on cfg.
//
// If cfg.Enabled is false, a no-op logger is returned (all methods are safe to call
// but emit nothing). If cfg.Output is "stderr" or empty, events are written to
// os.Stderr. Otherwise, the file at cfg.Output is opened in append+create mode
// with 0640 permissions — the parent directory must already exist.
//
// Returns an error only if a file path is configured but cannot be opened.
func NewLogger(cfg Config) (*Logger, error) {
	if !cfg.Enabled {
		return Disabled(), nil
	}
	switch cfg.Output {
	case "", "stderr":
		return newLoggerFromWriter(os.Stderr), nil
	default:
		f, err := os.OpenFile(cfg.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, fmt.Errorf("audit: open %q: %w", cfg.Output, err)
		}
		l := newLoggerFromWriter(f)
		l.closeFn = f.Close
		return l, nil
	}
}

// Disabled returns a no-op logger. All methods are safe to call and emit nothing.
func Disabled() *Logger {
	return newLoggerFromWriter(io.Discard)
}

// newLoggerFromWriter creates a logger writing to w. Used by tests to capture output.
func newLoggerFromWriter(w io.Writer) *Logger {
	return &Logger{
		slog: slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
	}
}

// Close closes the underlying file if one was opened. No-op for stderr or discard writers.
func (l *Logger) Close() error {
	if l.closeFn != nil {
		return l.closeFn()
	}
	return nil
}

// MACIPChange logs a MAC address change for an IP.
// Fields: event_type, ip, subnet, old_mac, new_mac, old_vendor, new_vendor.
func (l *Logger) MACIPChange(ip net.IP, subnet string, oldMAC, newMAC net.HardwareAddr, oldVendor, newVendor string) {
	l.slog.Info("audit",
		slog.String("event_type", string(EventMACIPChange)),
		slog.String("ip", ip.String()),
		slog.String("subnet", subnet),
		slog.String("old_mac", oldMAC.String()),
		slog.String("new_mac", newMAC.String()),
		slog.String("old_vendor", oldVendor),
		slog.String("new_vendor", newVendor),
	)
}

// NewHost logs discovery of a previously unseen host.
// Fields: event_type, ip, subnet, mac, vendor, hostname.
func (l *Logger) NewHost(ip net.IP, subnet string, mac net.HardwareAddr, vendor, hostname string) {
	l.slog.Info("audit",
		slog.String("event_type", string(EventNewHost)),
		slog.String("ip", ip.String()),
		slog.String("subnet", subnet),
		slog.String("mac", mac.String()),
		slog.String("vendor", vendor),
		slog.String("hostname", hostname),
	)
}

// HostDisappeared logs a host going stale (not seen within the staleness threshold).
// Fields: event_type, ip, subnet, mac, vendor, last_seen.
func (l *Logger) HostDisappeared(ip net.IP, subnet string, mac net.HardwareAddr, vendor string, lastSeen time.Time) {
	l.slog.Info("audit",
		slog.String("event_type", string(EventHostDisappeared)),
		slog.String("ip", ip.String()),
		slog.String("subnet", subnet),
		slog.String("mac", mac.String()),
		slog.String("vendor", vendor),
		slog.Time("last_seen", lastSeen),
	)
}

// UnauthorizedDevice logs detection of a device not on the MAC allowlist.
// Fields: event_type, ip, subnet, mac, vendor.
func (l *Logger) UnauthorizedDevice(ip net.IP, subnet string, mac net.HardwareAddr, vendor string) {
	l.slog.Info("audit",
		slog.String("event_type", string(EventUnauthorizedDevice)),
		slog.String("ip", ip.String()),
		slog.String("subnet", subnet),
		slog.String("mac", mac.String()),
		slog.String("vendor", vendor),
	)
}

// DuplicateIP logs detection of multiple MACs claiming the same IP within one ARP scan window.
// Fields: event_type, ip, subnet, primary_mac, duplicate_macs (JSON array of MAC strings).
func (l *Logger) DuplicateIP(ip net.IP, subnet string, primaryMAC net.HardwareAddr, duplicateMACs []net.HardwareAddr) {
	dupStrs := make([]string, len(duplicateMACs))
	for i, mac := range duplicateMACs {
		dupStrs[i] = mac.String()
	}
	l.slog.Info("audit",
		slog.String("event_type", string(EventDuplicateIP)),
		slog.String("ip", ip.String()),
		slog.String("subnet", subnet),
		slog.String("primary_mac", primaryMAC.String()),
		slog.Any("duplicate_macs", dupStrs),
	)
}

// ScanCycleComplete logs completion of a full scan cycle for a subnet.
// Fields: event_type, subnet, hosts_found, duration_seconds, scanners_run.
func (l *Logger) ScanCycleComplete(subnet string, hostsFound int, duration time.Duration, scannersRun []string) {
	l.slog.Info("audit",
		slog.String("event_type", string(EventScanCycleComplete)),
		slog.String("subnet", subnet),
		slog.Int("hosts_found", hostsFound),
		slog.Float64("duration_seconds", duration.Seconds()),
		slog.Any("scanners_run", scannersRun),
	)
}
