//go:build !linux

package main

import "io/fs"

// Non-Linux targets do not expose a portable POSIX UID/GID interface here.
// Their filesystem ACLs remain managed by the platform; CompactDB still
// applies its secure mode policy where supported.
func preserveFileOwnership(_ string, _ fs.FileInfo) error { return nil }
