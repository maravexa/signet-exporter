//go:build !windows

package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenAuditFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.log")
	if err := os.WriteFile(target, []byte("audit"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "audit.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openAuditFile(link); err == nil {
		t.Fatal("audit symlink was accepted")
	}
}
