package audit

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// Logger wraps slog to emit structured JSON audit records.
type Logger struct {
	log *slog.Logger
}

// New creates an audit Logger. output may be "stderr" or a file path.
func New(output string) (*Logger, error) {
	var w io.Writer
	switch output {
	case "", "stderr":
		w = os.Stderr
	default:
		f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return nil, err
		}
		w = f
	}

	log := slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	return &Logger{log: log}, nil
}

// MACChange records a MAC address change event.
func (l *Logger) MACChange(ctx context.Context, ip, oldMAC, newMAC string) {
	l.log.InfoContext(ctx, "mac_ip_binding_changed",
		slog.String("event", "mac_change"),
		slog.String("ip", ip),
		slog.String("old_mac", oldMAC),
		slog.String("new_mac", newMAC),
	)
}

// UnauthorizedDevice records detection of a device not in the allowlist.
func (l *Logger) UnauthorizedDevice(ctx context.Context, ip, mac, vendor, subnet string) {
	l.log.InfoContext(ctx, "unauthorized_device_detected",
		slog.String("event", "unauthorized_device"),
		slog.String("ip", ip),
		slog.String("mac", mac),
		slog.String("vendor", vendor),
		slog.String("subnet", subnet),
	)
}

// ScanComplete records the completion of a subnet scan.
func (l *Logger) ScanComplete(ctx context.Context, subnet, scanner string, hostsFound int) {
	l.log.InfoContext(ctx, "scan_complete",
		slog.String("event", "scan_complete"),
		slog.String("subnet", subnet),
		slog.String("scanner", scanner),
		slog.Int("hosts_found", hostsFound),
	)
}
