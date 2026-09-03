package main

import (
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestCompactDBPreservesDataAndSecureReplacementMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := bolt.Open(path, 0o660, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucket([]byte("state"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte("key"), []byte("value"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	// Compaction must not carry a world-readable source mode into replacement.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := CompactDB(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o640); got != want {
		t.Fatalf("replacement mode = %#o, want %#o", got, want)
	}

	db, err = bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := db.View(func(tx *bolt.Tx) error {
		got := tx.Bucket([]byte("state")).Get([]byte("key"))
		if string(got) != "value" {
			t.Fatalf("compacted data = %q, want value", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCompactDBIgnoresOrphanedPriorTempName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	orphan := path + ".compact.tmp"
	if err := os.WriteFile(orphan, []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CompactDB(path); err != nil {
		t.Fatalf("compact with orphaned prior temp: %v", err)
	}
	if _, err := os.Stat(orphan); err != nil {
		t.Fatalf("compaction must not delete an unrelated orphan: %v", err)
	}
}
