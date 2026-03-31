// Package version holds build-time version variables set via -ldflags.
package version

// Build-time variables set via -ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)
