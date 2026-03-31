package version

// Build-time variables set via -ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)
