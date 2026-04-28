// Package buildinfo exposes release metadata injected at build time.
package buildinfo

import "fmt"

var (
	// Version is the semantic version injected by the build pipeline.
	Version = "dev"
	// Commit is the short git revision injected by the build pipeline.
	Commit = "unknown"
)

// Summary returns a human-readable build string.
func Summary() string {
	if Commit == "" || Commit == "unknown" {
		return Version
	}
	return fmt.Sprintf("%s (%s)", Version, Commit)
}
