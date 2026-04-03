package scanner

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// writeAllowlistFile creates a temp file with the given content and returns its path.
func writeAllowlistFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "allowlist.txt")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAllowlist_ValidFile(t *testing.T) {
	content := `# MAC allowlist
aa:bb:cc:dd:ee:ff
AA-BB-CC-11-22-33
aabbcc445566
`
	path := writeAllowlistFile(t, content)
	al, err := LoadAllowlist(path)
	if err != nil {
		t.Fatalf("LoadAllowlist error: %v", err)
	}
	if al == nil {
		t.Fatal("expected non-nil allowlist")
	}
	if got := al.Len(); got != 3 {
		t.Errorf("Len() = %d, want 3", got)
	}

	cases := []struct {
		mac  string
		want bool
	}{
		{"aa:bb:cc:dd:ee:ff", true},
		{"AA:BB:CC:DD:EE:FF", true}, // case-insensitive
		{"aa:bb:cc:11:22:33", true},
		{"aa:bb:cc:44:55:66", true},
		{"00:11:22:33:44:55", false}, // not in list
	}
	for _, tc := range cases {
		hw, err := net.ParseMAC(tc.mac)
		if err != nil {
			t.Fatalf("ParseMAC(%q): %v", tc.mac, err)
		}
		if got := al.Contains(hw); got != tc.want {
			t.Errorf("Contains(%q) = %v, want %v", tc.mac, got, tc.want)
		}
	}
}

func TestLoadAllowlist_EmptyPath(t *testing.T) {
	al, err := LoadAllowlist("")
	if err != nil {
		t.Fatalf("LoadAllowlist(\"\") returned error: %v", err)
	}
	if al != nil {
		t.Errorf("LoadAllowlist(\"\") = non-nil, want nil (no allowlist configured)")
	}
}

func TestLoadAllowlist_MissingFile(t *testing.T) {
	_, err := LoadAllowlist("/nonexistent/path/allowlist.txt")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadAllowlist_EmptyFile(t *testing.T) {
	path := writeAllowlistFile(t, "")
	al, err := LoadAllowlist(path)
	if err != nil {
		t.Fatalf("LoadAllowlist of empty file: %v", err)
	}
	if al == nil {
		t.Fatal("expected non-nil allowlist for empty file")
	}
	if al.Len() != 0 {
		t.Errorf("Len() = %d, want 0 for empty file", al.Len())
	}
}

func TestLoadAllowlist_CommentsAndBlanks(t *testing.T) {
	content := `
# This is a comment
  # Indented comment

aa:bb:cc:dd:ee:01

# Another comment
bb:cc:dd:ee:ff:02
`
	path := writeAllowlistFile(t, content)
	al, err := LoadAllowlist(path)
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	if got := al.Len(); got != 2 {
		t.Errorf("Len() = %d, want 2 (comments and blanks excluded)", got)
	}
	hw1, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	hw2, _ := net.ParseMAC("bb:cc:dd:ee:ff:02")
	if !al.Contains(hw1) {
		t.Error("does not contain aa:bb:cc:dd:ee:01")
	}
	if !al.Contains(hw2) {
		t.Error("does not contain bb:cc:dd:ee:ff:02")
	}
}

func TestLoadAllowlist_DuplicateMACs(t *testing.T) {
	content := `aa:bb:cc:dd:ee:ff
AA:BB:CC:DD:EE:FF
AA-BB-CC-DD-EE-FF
aabbccddeeff
`
	path := writeAllowlistFile(t, content)
	al, err := LoadAllowlist(path)
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	if got := al.Len(); got != 1 {
		t.Errorf("Len() = %d, want 1 (all are the same MAC, deduplicated)", got)
	}
}

func TestLoadAllowlist_CaseNormalization(t *testing.T) {
	// Store one MAC in lowercase, look it up in uppercase (and vice versa).
	content := "aa:bb:cc:dd:ee:ff\n"
	path := writeAllowlistFile(t, content)
	al, err := LoadAllowlist(path)
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	// Lookup with uppercase MAC.
	upper, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	if !al.Contains(upper) {
		t.Error("Contains(uppercase) = false, want true — case normalization failed")
	}
	// Lookup with lowercase MAC.
	lower, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	if !al.Contains(lower) {
		t.Error("Contains(lowercase) = false, want true")
	}
}

func TestLoadAllowlist_MalformedLines(t *testing.T) {
	content := `# valid entries:
aa:bb:cc:dd:ee:01
not-a-mac
ZZZZZZZZZZZZ
00:11:22
bb:cc:dd:ee:ff:02
toolongforamac0011223344556677
`
	path := writeAllowlistFile(t, content)
	al, err := LoadAllowlist(path)
	if err != nil {
		t.Fatalf("LoadAllowlist should not error on malformed lines: %v", err)
	}
	// Only the two valid MACs should be present.
	if got := al.Len(); got != 2 {
		t.Errorf("Len() = %d, want 2 (valid MACs only)", got)
	}
	hw1, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	hw2, _ := net.ParseMAC("bb:cc:dd:ee:ff:02")
	if !al.Contains(hw1) {
		t.Error("does not contain aa:bb:cc:dd:ee:01")
	}
	if !al.Contains(hw2) {
		t.Error("does not contain bb:cc:dd:ee:ff:02")
	}
}

func TestContains_NilMAC(t *testing.T) {
	path := writeAllowlistFile(t, "aa:bb:cc:dd:ee:ff\n")
	al, err := LoadAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}
	// Must not panic; must return false.
	if al.Contains(nil) {
		t.Error("Contains(nil) = true, want false")
	}
}

func TestContains_NilAllowlist(t *testing.T) {
	// A nil *Allowlist must never be passed to Contains directly (callers guard it).
	// This test documents the caller pattern: check for nil before calling Contains.
	var al *Allowlist
	hw, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	if al != nil && al.Contains(hw) {
		t.Error("nil allowlist guard check failed")
	}
	// Verify the nil guard idiom evaluates correctly.
	authorized := al == nil || al.Contains(hw)
	if !authorized {
		t.Error("nil allowlist should be treated as permissive (all authorized)")
	}
}
