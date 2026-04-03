// Package oui provides an IEEE OUI vendor database parser and lookup.
package oui

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// Database holds the parsed IEEE OUI mappings.
type Database struct {
	vendors map[string]string // key: uppercase "AABBCC" (first 3 octets, no separators), value: vendor name
}

// LoadDatabase parses an IEEE OUI text file.
//
// The file format has lines like:
//
//	DC-A6-32   (hex)		Raspberry Pi Trading Ltd
//
// Only lines containing "(hex)" are parsed — the 3-byte prefix (left of "(hex)") is
// stripped of whitespace and dashes, uppercased, and used as the map key. The vendor
// name is taken from the right side of "(hex)", trimmed of whitespace.
//
// If path is empty, an empty database is returned with no error — this supports
// running without an OUI file configured.
// If the file cannot be opened, an error is returned.
// An empty or comment-only file returns an empty database with no error.
func LoadDatabase(path string) (*Database, error) {
	if path == "" {
		return &Database{vendors: make(map[string]string)}, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("oui: open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	db := &Database{vendors: make(map[string]string)}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "(hex)") {
			continue
		}
		parts := strings.SplitN(line, "(hex)", 2)
		if len(parts) != 2 {
			continue
		}
		// Left side: prefix like "DC-A6-32   " — strip whitespace and dashes, uppercase.
		prefix := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(parts[0]), "-", ""))
		if len(prefix) != 6 {
			continue
		}
		// Right side: vendor name like "\t\tRaspberry Pi Trading Ltd" — trim whitespace.
		vendor := strings.TrimSpace(parts[1])
		if vendor == "" {
			continue
		}
		db.vendors[prefix] = vendor
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("oui: read %q: %w", path, err)
	}
	return db, nil
}

// Lookup returns the vendor name for a MAC address, or "" if not found.
// Accepts any net.HardwareAddr with 3 or more bytes; uses the first 3 bytes as the OUI prefix.
// Returns "" for nil or short MACs without panicking.
func (db *Database) Lookup(mac net.HardwareAddr) string {
	if len(mac) < 3 {
		return ""
	}
	key := strings.ToUpper(fmt.Sprintf("%02X%02X%02X", mac[0], mac[1], mac[2]))
	return db.vendors[key]
}

// Len returns the number of entries in the database.
func (db *Database) Len() int {
	return len(db.vendors)
}
