// Package version holds build metadata, injected via -ldflags at release time.
package version

var (
	// Version is the semver tag of the build.
	Version = "dev"
	// Commit is the git SHA of the build.
	Commit = "none"
	// Date is the build timestamp.
	Date = "unknown"
)
