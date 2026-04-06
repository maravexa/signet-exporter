// Package audit provides structured audit logging for security-relevant events.
// Events can be emitted as JSON (default, one object per line) or CEF (Common
// Event Format, for SIEM integration).
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
	EventHostExpired        EventType = "host_expired"
	EventUnauthorizedDevice EventType = "unauthorized_device"
	EventScanCycleComplete  EventType = "scan_cycle_complete"
	EventDuplicateIP        EventType = "duplicate_ip_detected"
	EventScanCompleted      EventType = "scan_completed"
	EventScanError          EventType = "scan_error"
	EventConfigReloaded     EventType = "config_reloaded"
	EventCertReloaded       EventType = "cert_reloaded"
)

// auditBackend is the internal interface all formatters must satisfy.
// It mirrors every event method on Logger; Logger delegates to the backend.
type auditBackend interface {
	NewHost(ip net.IP, subnet string, mac net.HardwareAddr, vendor, hostname string)
	MACIPChange(ip net.IP, subnet string, oldMAC, newMAC net.HardwareAddr, oldVendor, newVendor string)
	HostDisappeared(ip net.IP, subnet string, mac net.HardwareAddr, vendor string, lastSeen time.Time)
	HostExpired(ip string, subnet string, lastSeen time.Time)
	UnauthorizedDevice(ip net.IP, subnet string, mac net.HardwareAddr, vendor string)
	DuplicateIP(ip net.IP, subnet string, primaryMAC net.HardwareAddr, duplicateMACs []net.HardwareAddr)
	ScanCycleComplete(subnet string, hostsFound int, duration time.Duration, scannersRun []string)
	ScanCompleted(subnet, scanner string, duration time.Duration, hostsFound int)
	ScanError(subnet, scanner string, err error)
	ConfigReloaded(changedFields []string)
	CertReloaded(certPath string, certErr error)
}

// Logger emits structured audit events to the configured backend.
// It is safe for concurrent use.
type Logger struct {
	backend auditBackend
	closeFn func() error // non-nil only when we opened a file
}

// Config holds audit logger configuration.
type Config struct {
	Enabled bool
	Format  string // "json" (default) or "cef"
	Output  string // "stderr" | "stdout" | "file" | <file_path> (backward compat)
	Path    string // file path when Output == "file"
	Version string // binary version injected into CEF header
}

// NewLogger creates an audit logger based on cfg.
//
// Format selects the output format: "json" (default) or "cef".
// Output controls the destination:
//   - "" or "stderr" → standard error
//   - "stdout"       → standard output
//   - "file"         → file at Path (parent directory must exist)
//   - anything else  → treated as a file path (backward compatibility)
//
// Returns an error only if a file path is configured but cannot be opened.
func NewLogger(cfg Config) (*Logger, error) {
	if !cfg.Enabled {
		return Disabled(), nil
	}

	w, closeFn, err := openWriter(cfg)
	if err != nil {
		return nil, err
	}

	var backend auditBackend
	switch cfg.Format {
	case "cef":
		backend = NewCEFFormatter(w, cfg.Version)
	default: // "json" or ""
		backend = newJSONBackend(w)
	}

	return &Logger{backend: backend, closeFn: closeFn}, nil
}

func openWriter(cfg Config) (io.Writer, func() error, error) {
	switch cfg.Output {
	case "stdout":
		return os.Stdout, nil, nil
	case "", "stderr":
		return os.Stderr, nil, nil
	case "file":
		path := cfg.Path
		if path == "" {
			path = "/var/log/signet/audit.log"
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, nil, fmt.Errorf("audit: open %q: %w", path, err)
		}
		return f, f.Close, nil
	default:
		// Backward compatibility: treat Output as a direct file path.
		f, err := os.OpenFile(cfg.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, nil, fmt.Errorf("audit: open %q: %w", cfg.Output, err)
		}
		return f, f.Close, nil
	}
}

// Disabled returns a no-op logger. All methods are safe to call and emit nothing.
func Disabled() *Logger {
	return &Logger{backend: noopBackend{}}
}

// newLoggerFromWriter creates a JSON logger writing to w. Used by tests.
func newLoggerFromWriter(w io.Writer) *Logger {
	return &Logger{backend: newJSONBackend(w)}
}

// Close closes the underlying file if one was opened. No-op for stderr, stdout, or discard.
func (l *Logger) Close() error {
	if l.closeFn != nil {
		return l.closeFn()
	}
	return nil
}

// ---- Event methods (delegated to backend) ----------------------------------

// MACIPChange logs a MAC address change for an IP.
func (l *Logger) MACIPChange(ip net.IP, subnet string, oldMAC, newMAC net.HardwareAddr, oldVendor, newVendor string) {
	l.backend.MACIPChange(ip, subnet, oldMAC, newMAC, oldVendor, newVendor)
}

// NewHost logs discovery of a previously unseen host.
func (l *Logger) NewHost(ip net.IP, subnet string, mac net.HardwareAddr, vendor, hostname string) {
	l.backend.NewHost(ip, subnet, mac, vendor, hostname)
}

// HostDisappeared logs a host going stale (not seen within the staleness threshold).
func (l *Logger) HostDisappeared(ip net.IP, subnet string, mac net.HardwareAddr, vendor string, lastSeen time.Time) {
	l.backend.HostDisappeared(ip, subnet, mac, vendor, lastSeen)
}

// HostExpired logs a host being pruned by the TTL eviction mechanism.
// ip is the string representation of the expired host's IP address.
// subnet is the subnet the host belonged to.
// lastSeen is the timestamp of the last scan in which the host was observed.
func (l *Logger) HostExpired(ip string, subnet string, lastSeen time.Time) {
	l.backend.HostExpired(ip, subnet, lastSeen)
}

// UnauthorizedDevice logs detection of a device not on the MAC allowlist.
func (l *Logger) UnauthorizedDevice(ip net.IP, subnet string, mac net.HardwareAddr, vendor string) {
	l.backend.UnauthorizedDevice(ip, subnet, mac, vendor)
}

// DuplicateIP logs detection of multiple MACs claiming the same IP.
func (l *Logger) DuplicateIP(ip net.IP, subnet string, primaryMAC net.HardwareAddr, duplicateMACs []net.HardwareAddr) {
	l.backend.DuplicateIP(ip, subnet, primaryMAC, duplicateMACs)
}

// ScanCycleComplete logs completion of a full scan cycle for a subnet.
func (l *Logger) ScanCycleComplete(subnet string, hostsFound int, duration time.Duration, scannersRun []string) {
	l.backend.ScanCycleComplete(subnet, hostsFound, duration, scannersRun)
}

// ScanCompleted logs completion of a single scanner pass within a cycle.
func (l *Logger) ScanCompleted(subnet, scanner string, duration time.Duration, hostsFound int) {
	l.backend.ScanCompleted(subnet, scanner, duration, hostsFound)
}

// ScanError logs a scanner failure.
func (l *Logger) ScanError(subnet, scanner string, err error) {
	l.backend.ScanError(subnet, scanner, err)
}

// ConfigReloaded logs a configuration reload. Stub for Phase 4 (config hot-reload).
func (l *Logger) ConfigReloaded(changedFields []string) {
	l.backend.ConfigReloaded(changedFields)
}

// CertReloaded logs a TLS certificate reload triggered by SIGHUP.
// certErr is non-nil when the reload failed; the old certificate remains active.
func (l *Logger) CertReloaded(certPath string, certErr error) {
	l.backend.CertReloaded(certPath, certErr)
}

// ---- jsonBackend -----------------------------------------------------------

// jsonBackend writes audit events as JSON lines using slog.
type jsonBackend struct {
	sl *slog.Logger
}

func newJSONBackend(w io.Writer) *jsonBackend {
	return &jsonBackend{
		sl: slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}
}

func (j *jsonBackend) NewHost(ip net.IP, subnet string, mac net.HardwareAddr, vendor, hostname string) {
	j.sl.Info("audit",
		slog.String("event_type", string(EventNewHost)),
		slog.String("ip", ip.String()),
		slog.String("subnet", subnet),
		slog.String("mac", mac.String()),
		slog.String("vendor", vendor),
		slog.String("hostname", hostname),
	)
}

func (j *jsonBackend) MACIPChange(ip net.IP, subnet string, oldMAC, newMAC net.HardwareAddr, oldVendor, newVendor string) {
	j.sl.Info("audit",
		slog.String("event_type", string(EventMACIPChange)),
		slog.String("ip", ip.String()),
		slog.String("subnet", subnet),
		slog.String("old_mac", oldMAC.String()),
		slog.String("new_mac", newMAC.String()),
		slog.String("old_vendor", oldVendor),
		slog.String("new_vendor", newVendor),
	)
}

func (j *jsonBackend) HostDisappeared(ip net.IP, subnet string, mac net.HardwareAddr, vendor string, lastSeen time.Time) {
	j.sl.Info("audit",
		slog.String("event_type", string(EventHostDisappeared)),
		slog.String("ip", ip.String()),
		slog.String("subnet", subnet),
		slog.String("mac", mac.String()),
		slog.String("vendor", vendor),
		slog.Time("last_seen", lastSeen),
	)
}

func (j *jsonBackend) HostExpired(ip string, subnet string, lastSeen time.Time) {
	j.sl.Info("audit",
		slog.String("event_type", string(EventHostExpired)),
		slog.String("ip", ip),
		slog.String("subnet", subnet),
		slog.Time("last_seen", lastSeen),
	)
}

func (j *jsonBackend) UnauthorizedDevice(ip net.IP, subnet string, mac net.HardwareAddr, vendor string) {
	j.sl.Info("audit",
		slog.String("event_type", string(EventUnauthorizedDevice)),
		slog.String("ip", ip.String()),
		slog.String("subnet", subnet),
		slog.String("mac", mac.String()),
		slog.String("vendor", vendor),
	)
}

func (j *jsonBackend) DuplicateIP(ip net.IP, subnet string, primaryMAC net.HardwareAddr, duplicateMACs []net.HardwareAddr) {
	dupStrs := make([]string, len(duplicateMACs))
	for i, mac := range duplicateMACs {
		dupStrs[i] = mac.String()
	}
	j.sl.Info("audit",
		slog.String("event_type", string(EventDuplicateIP)),
		slog.String("ip", ip.String()),
		slog.String("subnet", subnet),
		slog.String("primary_mac", primaryMAC.String()),
		slog.Any("duplicate_macs", dupStrs),
	)
}

func (j *jsonBackend) ScanCycleComplete(subnet string, hostsFound int, duration time.Duration, scannersRun []string) {
	j.sl.Info("audit",
		slog.String("event_type", string(EventScanCycleComplete)),
		slog.String("subnet", subnet),
		slog.Int("hosts_found", hostsFound),
		slog.Float64("duration_seconds", duration.Seconds()),
		slog.Any("scanners_run", scannersRun),
	)
}

func (j *jsonBackend) ScanCompleted(subnet, scanner string, duration time.Duration, hostsFound int) {
	j.sl.Info("audit",
		slog.String("event_type", string(EventScanCompleted)),
		slog.String("subnet", subnet),
		slog.String("scanner", scanner),
		slog.Float64("duration_seconds", duration.Seconds()),
		slog.Int("hosts_found", hostsFound),
	)
}

func (j *jsonBackend) ScanError(subnet, scanner string, err error) {
	j.sl.Warn("audit",
		slog.String("event_type", string(EventScanError)),
		slog.String("subnet", subnet),
		slog.String("scanner", scanner),
		slog.String("error", err.Error()),
	)
}

func (j *jsonBackend) ConfigReloaded(changedFields []string) {
	j.sl.Info("audit",
		slog.String("event_type", string(EventConfigReloaded)),
		slog.Any("changed_fields", changedFields),
	)
}

func (j *jsonBackend) CertReloaded(certPath string, certErr error) {
	if certErr != nil {
		j.sl.Warn("audit",
			slog.String("event_type", string(EventCertReloaded)),
			slog.String("cert_path", certPath),
			slog.String("error", certErr.Error()),
		)
		return
	}
	j.sl.Info("audit",
		slog.String("event_type", string(EventCertReloaded)),
		slog.String("cert_path", certPath),
	)
}

// ---- noopBackend -----------------------------------------------------------

// noopBackend discards all events. Used by Disabled().
type noopBackend struct{}

func (noopBackend) NewHost(net.IP, string, net.HardwareAddr, string, string)                       {}
func (noopBackend) MACIPChange(net.IP, string, net.HardwareAddr, net.HardwareAddr, string, string) {}
func (noopBackend) HostDisappeared(net.IP, string, net.HardwareAddr, string, time.Time)            {}
func (noopBackend) HostExpired(string, string, time.Time)                                          {}
func (noopBackend) UnauthorizedDevice(net.IP, string, net.HardwareAddr, string)                    {}
func (noopBackend) DuplicateIP(net.IP, string, net.HardwareAddr, []net.HardwareAddr)               {}
func (noopBackend) ScanCycleComplete(string, int, time.Duration, []string)                         {}
func (noopBackend) ScanCompleted(string, string, time.Duration, int)                               {}
func (noopBackend) ScanError(string, string, error)                                                {}
func (noopBackend) ConfigReloaded([]string)                                                        {}
func (noopBackend) CertReloaded(string, error)                                                     {}
