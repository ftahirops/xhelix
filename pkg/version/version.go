// Package version exposes the agent's build-time version string.
//
// The value is overridden at build time via -ldflags; see Makefile.
package version

// Version is the running agent's release identifier.
// Set at build time with:
//
//	go build -ldflags="-X github.com/xhelix/xhelix/pkg/version.Version=X.Y.Z"
var Version = "0.0.11-dev"

// Commit is the git commit short SHA, when available.
var Commit = "unknown"
