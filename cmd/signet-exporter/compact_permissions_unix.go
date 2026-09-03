//go:build linux

package main

import (
	"io/fs"
	"os"
	"syscall"
)

// preserveFileOwnership keeps an atomic compact-file replacement accessible to
// the same service account and group as the source database. Without this, a
// root-run compaction would replace a signet-owned database with root:root.
func preserveFileOwnership(path string, info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return os.Chown(path, int(stat.Uid), int(stat.Gid))
}
