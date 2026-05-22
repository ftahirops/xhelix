package main

import (
	"os"
	"strings"
)

// ANSI colour helpers. Used by egress observe / analytics output to
// flag suspicion levels at a glance. Falls back to plain text when
// stdout is not a TTY (so piped output stays parseable).

const (
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiGreen  = "\x1b[32m"
	ansiDim    = "\x1b[2m"
	ansiBold   = "\x1b[1m"
)

// useColor reports whether stdout is a TTY. Cached so each output
// row doesn't re-stat. Pure-stdlib: avoids a golang.org/x/term dep
// (which keeps pulling in newer go-version requirements).
var useColor = func() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("XHELIX_NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}()

func colorize(s, color string) string {
	if !useColor {
		return s
	}
	return color + s + ansiReset
}

// Suspicion is the per-row heuristic score for green/yellow/red.
type Suspicion int

const (
	SusGreen Suspicion = iota
	SusYellow
	SusRed
)

func (s Suspicion) Tag() string {
	switch s {
	case SusRed:
		return colorize("●", ansiRed)
	case SusYellow:
		return colorize("●", ansiYellow)
	}
	return colorize("●", ansiGreen)
}

// LineageSuspicion classifies a row from egress observe output.
//   - RED if: intel_bad > 0, OR shell-named app with any unique_unknown,
//     OR more than 10 unique unknowns
//   - YELLOW if: ≥3 unique unknowns, OR app is "(unidentified)" with
//     non-trivial traffic
//   - GREEN otherwise
//
// The heuristic is deliberately simple — it's a first-pass triage hint,
// not a verdict. Operators drill via xhelixctl egress observe --verbose.
func LineageSuspicion(app string, uniqueUnknown, intelBad int) Suspicion {
	if intelBad > 0 {
		return SusRed
	}
	if isShellApp(app) && uniqueUnknown > 0 {
		return SusRed
	}
	if uniqueUnknown >= 10 {
		return SusRed
	}
	if uniqueUnknown >= 3 {
		return SusYellow
	}
	if app == "(unidentified)" && uniqueUnknown > 0 {
		return SusYellow
	}
	return SusGreen
}

func isShellApp(app string) bool {
	for _, s := range []string{"bash", "sh", "zsh", "dash", "fish", "ksh"} {
		if app == s || strings.HasPrefix(app, s+":") {
			return true
		}
	}
	return false
}
