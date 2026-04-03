package main

import (
	"fmt"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
)

// CompactDB performs an online compaction of the bbolt database at dbPath.
//
// It opens the source database in read-only mode, streams a compact copy
// via tx.WriteTo into a temp file alongside the original, then atomically
// renames the temp file into place. The exporter must not be running —
// bbolt uses file-level locking and the 1s open timeout will fail fast.
//
// Prints before/after sizes to stdout. Returns an error on any failure;
// callers should print it and exit 1.
func CompactDB(dbPath string) error {
	srcInfo, err := os.Stat(dbPath)
	if err != nil {
		return fmt.Errorf("stat %q: %w", dbPath, err)
	}
	beforeSize := srcInfo.Size()

	src, err := bolt.Open(dbPath, 0o600, &bolt.Options{ReadOnly: true, Timeout: time.Second}) //nolint:gosec // G304: path is operator-supplied argument
	if err != nil {
		return fmt.Errorf("open source db (is the exporter still running?): %w", err)
	}

	tmpPath := dbPath + ".compact.tmp"
	dst, err := os.Create(tmpPath) //nolint:gosec // G304: same directory as source
	if err != nil {
		_ = src.Close()
		return fmt.Errorf("create temp file: %w", err)
	}

	writeErr := src.View(func(tx *bolt.Tx) error {
		_, werr := tx.WriteTo(dst)
		return werr
	})
	_ = dst.Close()
	_ = src.Close()

	if writeErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write compact copy: %w", writeErr)
	}

	if err := os.Rename(tmpPath, dbPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace original with compact copy: %w", err)
	}

	afterInfo, err := os.Stat(dbPath)
	if err != nil {
		return fmt.Errorf("stat result: %w", err)
	}
	afterSize := afterInfo.Size()

	saved := beforeSize - afterSize
	pct := 0.0
	if beforeSize > 0 {
		pct = 100.0 * float64(saved) / float64(beforeSize)
	}

	fmt.Printf("Compaction complete:\n")
	fmt.Printf("  Before: %d bytes (%.1f MB)\n", beforeSize, float64(beforeSize)/1024/1024)
	fmt.Printf("  After:  %d bytes (%.1f MB)\n", afterSize, float64(afterSize)/1024/1024)
	fmt.Printf("  Saved:  %d bytes (%.1f%%)\n", saved, pct)

	return nil
}
