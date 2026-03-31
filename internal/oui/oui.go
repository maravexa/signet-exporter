// Package oui provides an IEEE OUI vendor database parser and lookup.
package oui

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// Database holds a parsed IEEE OUI vendor lookup table.
type Database struct {
	entries map[string]string // OUI prefix (uppercase, no separators) → vendor name
}

// LoadFile parses an IEEE OUI text file (ieee-oui.txt format) from disk.
func LoadFile(path string) (*Database, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("oui: open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	db := &Database{entries: make(map[string]string)}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// TODO: implement IEEE OUI format parsing (hex prefix + vendor name)
		_ = line
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("oui: read %q: %w", path, err)
	}
	return db, nil
}

// Lookup returns the vendor name for the given MAC address.
// Returns an empty string if no entry is found.
func (db *Database) Lookup(mac net.HardwareAddr) string {
	if len(mac) < 3 {
		return ""
	}
	// TODO: implement OUI prefix extraction and lookup
	key := strings.ToUpper(fmt.Sprintf("%02X%02X%02X", mac[0], mac[1], mac[2]))
	return db.entries[key]
}
