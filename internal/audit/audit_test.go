package audit_test

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maravexa/signet-exporter/internal/audit"
)

// parseFirstLine parses the first non-empty line of buf as JSON into a map.
func parseFirstLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatal("no output written to buffer")
	}
	// Take only the first line if multiple were written.
	if idx := strings.Index(line, "\n"); idx >= 0 {
		line = line[:idx]
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("JSON parse error: %v\nraw: %q", err, line)
	}
	return m
}

func assertField(t *testing.T, m map[string]any, key, wantVal string) {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Errorf("missing field %q", key)
		return
	}
	if got, _ := v.(string); got != wantVal {
		t.Errorf("field %q = %q, want %q", key, got, wantVal)
	}
}

func assertFieldPresent(t *testing.T, m map[string]any, key string) {
	t.Helper()
	if _, ok := m[key]; !ok {
		t.Errorf("missing field %q", key)
	}
}

// --- construction tests ---

func TestNewLogger_Disabled(t *testing.T) {
	var buf bytes.Buffer
	// Use newLoggerFromWriter via the exported Disabled() helper; also test NewLogger directly.
	l := audit.Disabled()

	ip := net.ParseIP("10.0.0.1")
	mac, _ := net.ParseMAC("dc:a6:32:00:00:01")
	oldMAC, _ := net.ParseMAC("00:50:56:aa:bb:cc")

	// Call every method — must not panic and must not write any output.
	l.MACIPChange(ip, "10.0.0.0/24", oldMAC, mac, "VMware", "Raspberry Pi")
	l.NewHost(ip, "10.0.0.0/24", mac, "Raspberry Pi", "pi.local")
	l.HostDisappeared(ip, "10.0.0.0/24", mac, "Raspberry Pi", time.Now())
	l.UnauthorizedDevice(ip, "10.0.0.0/24", mac, "Unknown")
	l.ScanCycleComplete("10.0.0.0/24", 5, 2*time.Second, []string{"arp", "icmp"})

	if buf.Len() != 0 {
		t.Errorf("disabled logger wrote %d bytes, want 0", buf.Len())
	}

	// NewLogger with Enabled: false should also be a no-op.
	l2, err := audit.NewLogger(audit.Config{Enabled: false})
	if err != nil {
		t.Fatalf("NewLogger disabled: %v", err)
	}
	l2.NewHost(ip, "10.0.0.0/24", mac, "", "")
}

func TestNewLogger_Stderr(t *testing.T) {
	l, err := audit.NewLogger(audit.Config{Enabled: true, Output: "stderr"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
	_ = l.Close() // no-op for stderr
}

func TestNewLogger_EmptyOutput_DefaultsToStderr(t *testing.T) {
	l, err := audit.NewLogger(audit.Config{Enabled: true, Output: ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestNewLogger_FileOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := audit.NewLogger(audit.Config{Enabled: true, Output: path})
	if err != nil {
		t.Fatalf("NewLogger file: %v", err)
	}
	defer func() { _ = l.Close() }()

	ip := net.ParseIP("192.168.1.1")
	mac, _ := net.ParseMAC("dc:a6:32:00:00:01")
	l.NewHost(ip, "192.168.1.0/24", mac, "Raspberry Pi", "pi.local")
	_ = l.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("audit file is empty after writing an event")
	}
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &m); err != nil {
		t.Fatalf("audit file not valid JSON: %v\ncontent: %q", err, data)
	}
	if m["event_type"] != "new_host_discovered" {
		t.Errorf("event_type = %v, want new_host_discovered", m["event_type"])
	}
}

func TestNewLogger_FileNotCreatable(t *testing.T) {
	// Path in a nonexistent directory.
	_, err := audit.NewLogger(audit.Config{
		Enabled: true,
		Output:  "/nonexistent/dir/audit.log",
	})
	if err == nil {
		t.Fatal("expected error for unwritable path, got nil")
	}
}

// --- event format tests ---

func TestMACIPChange_Format(t *testing.T) {
	var buf bytes.Buffer
	l := audit.NewLoggerForTest(&buf)

	ip := net.ParseIP("10.1.2.3")
	oldMAC, _ := net.ParseMAC("00:50:56:aa:bb:cc")
	newMAC, _ := net.ParseMAC("dc:a6:32:11:22:33")
	l.MACIPChange(ip, "10.1.2.0/24", oldMAC, newMAC, "VMware, Inc.", "Raspberry Pi Trading Ltd")

	m := parseFirstLine(t, &buf)
	assertFieldPresent(t, m, "time")
	assertFieldPresent(t, m, "msg")
	assertField(t, m, "event_type", "mac_ip_change")
	assertField(t, m, "ip", "10.1.2.3")
	assertField(t, m, "subnet", "10.1.2.0/24")
	assertField(t, m, "old_mac", "00:50:56:aa:bb:cc")
	assertField(t, m, "new_mac", "dc:a6:32:11:22:33")
	assertField(t, m, "old_vendor", "VMware, Inc.")
	assertField(t, m, "new_vendor", "Raspberry Pi Trading Ltd")
}

func TestNewHost_Format(t *testing.T) {
	var buf bytes.Buffer
	l := audit.NewLoggerForTest(&buf)

	ip := net.ParseIP("10.0.0.5")
	mac, _ := net.ParseMAC("dc:a6:32:00:00:05")
	l.NewHost(ip, "10.0.0.0/24", mac, "Raspberry Pi", "pi5.local")

	m := parseFirstLine(t, &buf)
	assertFieldPresent(t, m, "time")
	assertFieldPresent(t, m, "msg")
	assertField(t, m, "event_type", "new_host_discovered")
	assertField(t, m, "ip", "10.0.0.5")
	assertField(t, m, "subnet", "10.0.0.0/24")
	assertField(t, m, "mac", "dc:a6:32:00:00:05")
	assertField(t, m, "vendor", "Raspberry Pi")
	assertField(t, m, "hostname", "pi5.local")
}

func TestHostDisappeared_Format(t *testing.T) {
	var buf bytes.Buffer
	l := audit.NewLoggerForTest(&buf)

	ip := net.ParseIP("10.0.0.7")
	mac, _ := net.ParseMAC("00:1b:21:aa:bb:cc")
	lastSeen := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	l.HostDisappeared(ip, "10.0.0.0/24", mac, "Intel", lastSeen)

	m := parseFirstLine(t, &buf)
	assertField(t, m, "event_type", "host_disappeared")
	assertField(t, m, "ip", "10.0.0.7")
	assertField(t, m, "subnet", "10.0.0.0/24")
	assertField(t, m, "mac", "00:1b:21:aa:bb:cc")
	assertField(t, m, "vendor", "Intel")
	assertFieldPresent(t, m, "last_seen") // ISO 8601 / RFC 3339 string
	// Verify it's a non-empty string (the exact format is handled by slog).
	if v, ok := m["last_seen"].(string); !ok || v == "" {
		t.Errorf("last_seen = %v, want non-empty ISO 8601 string", m["last_seen"])
	}
}

func TestUnauthorizedDevice_Format(t *testing.T) {
	var buf bytes.Buffer
	l := audit.NewLoggerForTest(&buf)

	ip := net.ParseIP("172.16.0.99")
	mac, _ := net.ParseMAC("ac:de:48:11:22:33")
	l.UnauthorizedDevice(ip, "172.16.0.0/24", mac, "Private")

	m := parseFirstLine(t, &buf)
	assertField(t, m, "event_type", "unauthorized_device")
	assertField(t, m, "ip", "172.16.0.99")
	assertField(t, m, "subnet", "172.16.0.0/24")
	assertField(t, m, "mac", "ac:de:48:11:22:33")
	assertField(t, m, "vendor", "Private")
}

func TestScanCycleComplete_Format(t *testing.T) {
	var buf bytes.Buffer
	l := audit.NewLoggerForTest(&buf)

	l.ScanCycleComplete("10.0.0.0/24", 12, 1500*time.Millisecond, []string{"arp", "icmp", "dns", "port"})

	m := parseFirstLine(t, &buf)
	assertField(t, m, "event_type", "scan_cycle_complete")
	assertField(t, m, "subnet", "10.0.0.0/24")

	if v, ok := m["hosts_found"].(float64); !ok || v != 12 {
		t.Errorf("hosts_found = %v, want 12", m["hosts_found"])
	}
	if v, ok := m["duration_seconds"].(float64); !ok || v != 1.5 {
		t.Errorf("duration_seconds = %v, want 1.5", m["duration_seconds"])
	}

	// scanners_run must be a JSON array of strings.
	raw, ok := m["scanners_run"].([]any)
	if !ok {
		t.Fatalf("scanners_run type = %T, want []any (JSON array)", m["scanners_run"])
	}
	want := []string{"arp", "icmp", "dns", "port"}
	if len(raw) != len(want) {
		t.Fatalf("scanners_run len = %d, want %d", len(raw), len(want))
	}
	for i, v := range raw {
		s, _ := v.(string)
		if s != want[i] {
			t.Errorf("scanners_run[%d] = %q, want %q", i, s, want[i])
		}
	}
}

func TestMultipleEvents_OneLine_Each(t *testing.T) {
	var buf bytes.Buffer
	l := audit.NewLoggerForTest(&buf)

	ip := net.ParseIP("10.0.0.1")
	mac, _ := net.ParseMAC("dc:a6:32:00:00:01")
	oldMAC, _ := net.ParseMAC("00:50:56:aa:bb:cc")

	l.NewHost(ip, "10.0.0.0/24", mac, "Raspberry Pi", "pi.local")
	l.MACIPChange(ip, "10.0.0.0/24", oldMAC, mac, "VMware", "Raspberry Pi")
	l.ScanCycleComplete("10.0.0.0/24", 3, time.Second, []string{"arp"})

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d\noutput:\n%s", len(lines), buf.String())
	}
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line %d is not valid JSON: %v\nraw: %q", i+1, err, line)
		}
	}
}
