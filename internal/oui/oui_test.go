package oui_test

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/maravexa/signet-exporter/internal/oui"
)

// sampleOUIFile returns the path to a temp file with a small but valid OUI dataset.
func sampleOUIFile(t *testing.T) string {
	t.Helper()
	content := `OUI/MA-L			Organization
company_id			Organization
				Address

DC-A6-32   (hex)		Raspberry Pi Trading Ltd
DCA632     (base 16)		Raspberry Pi Trading Ltd
				Maurice Wilkes Building, Cowley Road
				Cambridge    CB4 0DS
				GB

00-50-56   (hex)		VMware, Inc.
005056     (base 16)		VMware, Inc.
				3401 Hillview Ave
				Palo Alto  CA  94304
				US

AC-DE-48   (hex)		Private
ACDE48     (base 16)		Private

00-0C-29   (hex)		VMware, Inc.
000C29     (base 16)		VMware, Inc.
				3401 Hillview Ave
				Palo Alto  CA  94304
				US
`
	p := filepath.Join(t.TempDir(), "oui.txt")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDatabase_ValidFile(t *testing.T) {
	db, err := oui.LoadDatabase(sampleOUIFile(t))
	if err != nil {
		t.Fatalf("LoadDatabase returned error: %v", err)
	}
	if db == nil {
		t.Fatal("LoadDatabase returned nil database")
	}
	// Expect 4 (hex) lines → 4 entries.
	if got := db.Len(); got != 4 {
		t.Errorf("Len() = %d, want 4", got)
	}

	cases := []struct {
		mac    string
		vendor string
	}{
		{"dc:a6:32:00:00:01", "Raspberry Pi Trading Ltd"},
		{"00:50:56:aa:bb:cc", "VMware, Inc."},
		{"ac:de:48:11:22:33", "Private"},
		{"00:0c:29:fe:dc:ba", "VMware, Inc."},
	}
	for _, tc := range cases {
		hw, err := net.ParseMAC(tc.mac)
		if err != nil {
			t.Fatalf("ParseMAC(%q): %v", tc.mac, err)
		}
		if got := db.Lookup(hw); got != tc.vendor {
			t.Errorf("Lookup(%q) = %q, want %q", tc.mac, got, tc.vendor)
		}
	}
}

func TestLoadDatabase_EmptyPath(t *testing.T) {
	db, err := oui.LoadDatabase("")
	if err != nil {
		t.Fatalf("LoadDatabase(\"\") returned error: %v", err)
	}
	if db == nil {
		t.Fatal("LoadDatabase(\"\") returned nil database")
	}
	if db.Len() != 0 {
		t.Errorf("Len() = %d, want 0", db.Len())
	}
	hw, _ := net.ParseMAC("dc:a6:32:00:00:01")
	if got := db.Lookup(hw); got != "" {
		t.Errorf("Lookup on empty database = %q, want \"\"", got)
	}
}

func TestLoadDatabase_MissingFile(t *testing.T) {
	_, err := oui.LoadDatabase("/nonexistent/path/to/oui.txt")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadDatabase_EmptyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "oui.txt")
	if err := os.WriteFile(p, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := oui.LoadDatabase(p)
	if err != nil {
		t.Fatalf("LoadDatabase of empty file returned error: %v", err)
	}
	if db.Len() != 0 {
		t.Errorf("Len() = %d, want 0 for empty file", db.Len())
	}
}

func TestLoadDatabase_MalformedLines(t *testing.T) {
	content := `# This is a comment
blank line above

not-a-hex-entry  (hex)  ShouldBeSkipped_bad_prefix_length
DC-A6-32   (hex)		Raspberry Pi Trading Ltd
   (hex)   EmptyPrefix_ShouldBeSkipped
00-50-56   (hex)		VMware, Inc.
00-50-56   (hex)
some random text without the magic string
12-34-56   (hex)		TestVendor
`
	p := filepath.Join(t.TempDir(), "oui.txt")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := oui.LoadDatabase(p)
	if err != nil {
		t.Fatalf("LoadDatabase returned error: %v", err)
	}
	// Expect: DC-A6-32 → Raspberry Pi, 00-50-56 → VMware, 12-34-56 → TestVendor.
	// "not-a-hex-entry" has wrong prefix length → skipped.
	// Empty prefix line → skipped.
	// "00-50-56 (hex)" with empty vendor → skipped.
	if got := db.Len(); got != 3 {
		t.Errorf("Len() = %d, want 3", got)
	}
	hw, _ := net.ParseMAC("dc:a6:32:00:00:01")
	if got := db.Lookup(hw); got != "Raspberry Pi Trading Ltd" {
		t.Errorf("Lookup(dc:a6:32) = %q, want \"Raspberry Pi Trading Ltd\"", got)
	}
	hw2, _ := net.ParseMAC("12:34:56:78:9a:bc")
	if got := db.Lookup(hw2); got != "TestVendor" {
		t.Errorf("Lookup(12:34:56) = %q, want \"TestVendor\"", got)
	}
}

func TestLookup_KnownVendors(t *testing.T) {
	db, err := oui.LoadDatabase(sampleOUIFile(t))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		mac           string
		wantSubstring string
	}{
		{"00:50:56:aa:bb:cc", "VMware"},
		{"dc:a6:32:00:00:01", "Raspberry Pi"},
		{"00:00:00:00:00:00", ""}, // not in our sample file
	}
	for _, tc := range cases {
		hw, _ := net.ParseMAC(tc.mac)
		got := db.Lookup(hw)
		if tc.wantSubstring == "" {
			if got != "" {
				t.Errorf("Lookup(%q) = %q, want \"\"", tc.mac, got)
			}
		} else {
			if got == "" {
				t.Errorf("Lookup(%q) = \"\", want string containing %q", tc.mac, tc.wantSubstring)
			}
		}
	}
}

func TestLookup_NilMAC(t *testing.T) {
	db, err := oui.LoadDatabase("")
	if err != nil {
		t.Fatal(err)
	}
	// Must not panic; must return "".
	got := db.Lookup(nil)
	if got != "" {
		t.Errorf("Lookup(nil) = %q, want \"\"", got)
	}
}

func TestLookup_ShortMAC(t *testing.T) {
	db, err := oui.LoadDatabase("")
	if err != nil {
		t.Fatal(err)
	}
	short := net.HardwareAddr{0xdc, 0xa6} // only 2 bytes
	got := db.Lookup(short)
	if got != "" {
		t.Errorf("Lookup(2-byte MAC) = %q, want \"\"", got)
	}
}
