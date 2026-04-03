package scanner

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
)

// Allowlist holds a set of normalized MAC addresses considered authorized for a subnet.
// It is immutable after construction — no mutex needed.
type Allowlist struct {
	macs map[string]bool // key: uppercase colon-separated MAC (e.g. "AA:BB:CC:DD:EE:FF")
}

// LoadAllowlist parses a MAC allowlist file.
//
// File format: one MAC address per line. Lines starting with '#' are comments; blank lines
// are ignored. MACs may be colon-separated (aa:bb:cc:dd:ee:ff), dash-separated
// (AA-BB-CC-DD-EE-FF), or bare hex (aabbccddeeff). All formats are normalized to uppercase
// colon-separated for storage and comparison.
//
// Malformed lines are logged as warnings and skipped; they do not cause the load to fail.
//
// If path is empty, returns nil, nil — a nil *Allowlist means "no allowlist configured"
// (permissive default: all hosts are treated as authorized).
// An empty file returns an empty (restrictive) allowlist with no error.
// A missing file returns an error.
func LoadAllowlist(path string) (*Allowlist, error) {
	if path == "" {
		return nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("allowlist: open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	al := &Allowlist{macs: make(map[string]bool)}
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		normalized, err := normalizeMAC(line)
		if err != nil {
			slog.Warn("allowlist: skipping malformed line",
				"path", path,
				"line", lineNum,
				"content", line,
				"err", err,
			)
			continue
		}
		al.macs[normalized] = true
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("allowlist: read %q: %w", path, err)
	}
	return al, nil
}

// Contains returns true if mac is in the allowlist.
// Returns false for nil or zero-length MACs.
func (a *Allowlist) Contains(mac net.HardwareAddr) bool {
	if len(mac) == 0 {
		return false
	}
	return a.macs[strings.ToUpper(mac.String())]
}

// Len returns the number of entries in the allowlist.
func (a *Allowlist) Len() int {
	return len(a.macs)
}

// normalizeMAC converts any common MAC format to uppercase colon-separated.
// Accepts colon-separated, dash-separated, and bare 12-char hex strings.
func normalizeMAC(s string) (string, error) {
	// Strip separators to get raw hex.
	stripped := strings.NewReplacer(":", "", "-", "").Replace(s)
	if len(stripped) != 12 {
		return "", fmt.Errorf("expected 12 hex characters after stripping separators, got %d", len(stripped))
	}
	// Reformat with colons so net.ParseMAC can parse it.
	formatted := fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		stripped[0:2], stripped[2:4], stripped[4:6],
		stripped[6:8], stripped[8:10], stripped[10:12],
	)
	hw, err := net.ParseMAC(strings.ToLower(formatted))
	if err != nil {
		return "", err
	}
	return strings.ToUpper(hw.String()), nil
}
