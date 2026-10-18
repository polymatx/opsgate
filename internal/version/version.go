// Package version holds build metadata, injected via -ldflags at release time.
package version

import "runtime/debug"

var (
	// Version is the semver tag of the build.
	Version = "dev"
	// Commit is the git SHA of the build.
	Commit = "none"
	// Date is the build timestamp.
	Date = "unknown"
)

func init() {
	if Version != "dev" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		Version = v
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if Commit == "none" && len(s.Value) >= 7 {
				Commit = s.Value[:7]
			}
		case "vcs.time":
			if Date == "unknown" {
				Date = s.Value
			}
		}
	}
}
