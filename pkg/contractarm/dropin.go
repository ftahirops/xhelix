// Package contractarm arms a compiled contract's staged seccomp/AppArmor
// profiles by installing systemd unit drop-ins (P5a.2).
//
// Arming uses systemd's NATIVE enforcement directives — SystemCallFilter=
// for seccomp and AppArmorProfile= for AppArmor — written to a unit
// drop-in under /etc/systemd/system/<unit>.d/. No wrapper binary, no
// ExecStart rewriting. The kernel applies the filter when the service
// (re)starts, so arming is non-disruptive: it writes the drop-in and
// reloads systemd, but does NOT restart the service. The operator
// triggers the restart explicitly when ready.
package contractarm

import (
	"fmt"
	"strings"
	"time"
)

// DropInName is the unit drop-in filename xhelix manages. The numeric
// prefix orders it late so it overlays the vendor unit; the fixed name
// makes Disarm a simple delete.
func DropInName(app string) string {
	return "50-xhelix-" + sanitize(app) + ".conf"
}

// RenderDropIn produces the systemd drop-in text for one service.
//
//   - seccompDirective is the "SystemCallFilter=~…" line (may be empty).
//   - apparmorProfile is the loaded AppArmor profile name (may be empty
//     when AppArmor is unavailable or the profile wasn't loaded).
//   - egressDirective is the "IPAddressAllow=…\nIPAddressDeny=any" block
//     from EgressDirectives (may be empty when egress is not locked).
//
// Returns "" when there is nothing to enforce (no seccomp, no AppArmor,
// no egress).
func RenderDropIn(app, mode, unit, seccompDirective, apparmorProfile, egressDirective string, at time.Time) string {
	if seccompDirective == "" && apparmorProfile == "" && egressDirective == "" {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by xhelix contractcompiler (P5a.2). Do not edit by hand.\n")
	fmt.Fprintf(&b, "# app=%s mode=%s armed=%s\n", app, mode, at.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "# unit=%s\n", unit)
	b.WriteString("[Service]\n")
	if seccompDirective != "" {
		b.WriteString(seccompDirective)
		b.WriteString("\n")
		// EPERM (not SIGKILL) so the deception layer can still observe
		// the failed intent — consistent with pkg/prevent/seccomp.
		b.WriteString("SystemCallErrorNumber=EPERM\n")
	}
	if apparmorProfile != "" {
		fmt.Fprintf(&b, "AppArmorProfile=%s\n", apparmorProfile)
	}
	if egressDirective != "" {
		b.WriteString(egressDirective)
		b.WriteString("\n")
	}
	return b.String()
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, " ", "_")
	if s == "" {
		return "app"
	}
	return s
}
