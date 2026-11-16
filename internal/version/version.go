// Package version exposes build metadata. Values are injected at build time
// via -ldflags (see the Makefile); the defaults identify an untagged dev build.
package version

// These are variables (not constants) so the linker can override them:
//
//	-X go.privatebychoice.com/shellshawk/internal/version.Version=1.0.7
var (
	// Version is the release version, 1.0.x where x is the build number.
	Version = "dev"
	// Commit is the short VCS revision the binary was built from.
	Commit = "unknown"
	// BuildDate is the UTC build timestamp in RFC 3339 format.
	BuildDate = "unknown"
)

// Info is the build metadata as a value, suitable for JSON encoding.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
}

// Get returns the current build metadata.
func Get() Info {
	return Info{Version: Version, Commit: Commit, BuildDate: BuildDate}
}
