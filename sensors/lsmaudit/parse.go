// Package lsmaudit observes AppArmor and SELinux denial events.
//
// Both LSMs emit kernel audit messages when they block an action.
// A denial means policy *already stopped* a malicious operation —
// it is the highest-signal class of event xhelix can ingest because
// the false-positive rate is essentially the host's own policy
// hygiene.
//
// Sources are journald (preferred when present), /var/log/audit/audit.log
// (auditd-managed hosts), and /var/log/kern.log as a last resort.
//
// Phase 7 ships the parser + a tailing sensor; Phase 8 will optionally
// gate xhelix's own quarantine/block on whether AppArmor/SELinux
// already denied the action (avoid double-action).
package lsmaudit

import (
	"regexp"
	"strings"

	"github.com/xhelix/xhelix/pkg/model"
)

// Verdict is the output of parsing a single audit line.
type Verdict struct {
	LSM       string // "apparmor" | "selinux"
	Action    string // "DENIED" | "ALLOWED" | "AUDIT" (apparmor) | "denied" (selinux)
	Operation string // apparmor operation (e.g., "open", "exec")
	Profile   string // apparmor profile name
	PID       string
	Comm      string
	Path      string // affected file path
	Class     string // selinux tclass (file, dir, process, ...)
	SContext  string // selinux source context
	TContext  string // selinux target context
	Raw       string
}

var (
	reKV = regexp.MustCompile(`(\w+)=(?:"([^"]*)"|(\S+))`)
)

// Parse extracts a Verdict from a single audit line. Returns ok=false
// when the line is not an apparmor/selinux record.
//
// Recognised line shapes:
//
//   ... apparmor="DENIED" operation="open" profile="/usr/sbin/cupsd" name="/etc/shadow" pid=1234 comm="cupsd" ...
//   ... type=AVC msg=audit(...): avc: denied { read } for pid=1234 comm="curl" name="shadow" scontext=... tcontext=... tclass=file ...
func Parse(line string) (Verdict, bool) {
	line = strings.TrimRight(line, "\r\n")
	switch {
	case strings.Contains(line, "apparmor="):
		return parseAppArmor(line)
	case strings.Contains(line, "type=AVC") || strings.Contains(line, "avc:"):
		return parseSELinux(line)
	}
	return Verdict{}, false
}

func parseAppArmor(line string) (Verdict, bool) {
	v := Verdict{LSM: "apparmor", Raw: line}
	for _, m := range reKV.FindAllStringSubmatch(line, -1) {
		key := m[1]
		val := m[2]
		if val == "" {
			val = m[3]
		}
		switch key {
		case "apparmor":
			v.Action = strings.ToUpper(val)
		case "operation":
			v.Operation = val
		case "profile":
			v.Profile = val
		case "name":
			v.Path = val
		case "pid":
			v.PID = val
		case "comm":
			v.Comm = val
		}
	}
	if v.Action == "" {
		return v, false
	}
	return v, true
}

func parseSELinux(line string) (Verdict, bool) {
	v := Verdict{LSM: "selinux", Raw: line}
	// "avc: denied { read }"
	if idx := strings.Index(line, "avc:"); idx >= 0 {
		rest := line[idx+4:]
		rest = strings.TrimSpace(rest)
		// First token is "denied" / "granted"
		if i := strings.IndexByte(rest, ' '); i > 0 {
			v.Action = rest[:i]
		}
		// Operation set in braces { ... }
		if i := strings.Index(rest, "{"); i >= 0 {
			if j := strings.Index(rest[i:], "}"); j > 0 {
				v.Operation = strings.TrimSpace(rest[i+1 : i+j])
			}
		}
	}
	for _, m := range reKV.FindAllStringSubmatch(line, -1) {
		key := m[1]
		val := m[2]
		if val == "" {
			val = m[3]
		}
		switch key {
		case "pid":
			v.PID = val
		case "comm":
			v.Comm = val
		case "path", "name":
			if v.Path == "" {
				v.Path = val
			}
		case "tclass":
			v.Class = val
		case "scontext":
			v.SContext = val
		case "tcontext":
			v.TContext = val
		}
	}
	if v.Action == "" {
		return v, false
	}
	return v, true
}

// ToEvent projects a Verdict into a model.Event.
//
// DENIED / denied verdicts become Critical (policy already blocked
// a malicious action — extremely high signal). ALLOWED audit
// records become Notice; AUDIT-mode messages are Warn.
func ToEvent(v Verdict, host string) model.Event {
	sev := model.SeverityNotice
	switch strings.ToLower(v.Action) {
	case "denied":
		sev = model.SeverityCritical
	case "audit":
		sev = model.SeverityWarn
	}
	ev := model.NewEvent("lsm.audit", sev)
	ev.Host = host
	ev.Comm = v.Comm
	ev.Tags["lsm"] = v.LSM
	ev.Tags["action"] = v.Action
	ev.Tags["operation"] = v.Operation
	ev.Tags["profile"] = v.Profile
	ev.Tags["path"] = v.Path
	ev.Tags["pid"] = v.PID
	if v.Class != "" {
		ev.Tags["tclass"] = v.Class
	}
	if v.SContext != "" {
		ev.Tags["scontext"] = v.SContext
		ev.Tags["tcontext"] = v.TContext
	}
	return ev
}
