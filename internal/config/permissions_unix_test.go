//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateRegularFilePrivatePermissionPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateRegularFile(path, "key_file", true); err == nil {
		t.Fatal("world-readable private key was accepted")
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := validateRegularFile(path, "key_file", true); err != nil {
		t.Fatalf("group-readable private key rejected: %v", err)
	}
	if err := validateRegularFile(t.TempDir(), "key_file", true); err == nil {
		t.Fatal("directory accepted as private key")
	}
}

func TestValidateAuditPathPermissionPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte("audit"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateAuditPath(path, "path"); err == nil {
		t.Fatal("world-readable audit log was accepted")
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := validateAuditPath(path, "path"); err != nil {
		t.Fatalf("group-readable audit log rejected: %v", err)
	}
}

func TestSensitivePathsRejectSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := validateRegularFile(link, "key_file", true); err == nil {
		t.Fatal("private key symlink was accepted")
	}
	if err := validateAuditPath(link, "path"); err == nil {
		t.Fatal("audit log symlink was accepted")
	}
}
