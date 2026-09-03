//go:build !windows

package remotewrite

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialFilePermissionPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := mustBeRegular(path, "bearer_token_file", true); err == nil {
		t.Fatal("world-readable token was accepted")
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := mustBeRegular(path, "bearer_token_file", true); err != nil {
		t.Fatalf("group-readable token rejected: %v", err)
	}
	if err := mustBeRegular(t.TempDir(), "bearer_token_file", true); err == nil {
		t.Fatal("directory accepted as token")
	}
}

func TestCredentialFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "token")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "token-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := mustBeRegular(link, "bearer_token_file", true); err == nil {
		t.Fatal("credential symlink was accepted")
	}
}
