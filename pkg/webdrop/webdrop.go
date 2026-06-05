// Package webdrop detects a web-server worker writing executable PHP into a web
// root — the file-write half of a WordPress/PHP intrusion that pkg/webshellguard
// (process argv) misses. Real droppers run in-process inside php-fpm
// (file_put_contents + libcurl: no child process, no eval-in-argv), so the only
// host-level signal is the *write itself*: a php-fpm/apache/nginx worker
// creating a new .php in wp-content (plugins/themes/mu-plugins/uploads).
//
// It is fed by FIM events on web roots (which must be enabled — the 2026-06
// newbikebox breach was missed because FIM watched no /var/www paths). Pure-Go,
// no deps. The caller supplies the writing process + target path.
package webdrop

import (
	"path"
	"regexp"
	"strings"
)

type Severity uint8

const (
	SeverityNone     Severity = 0
	SeverityMedium   Severity = 3
	SeverityHigh     Severity = 4
	SeverityCritical Severity = 5
)

func (s Severity) String() string {
	switch s {
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	}
	return "none"
}

// Spec is one observed file write: the writing process and the target path.
type Spec struct {
	ActorComm string // e.g. "php-fpm"
	ActorExe  string // e.g. "/opt/plesk/php/8.3/sbin/php-fpm"
	Path      string // absolute target path written
}

// Verdict is the result. Hit=false means not a suspicious docroot PHP drop.
type Verdict struct {
	Hit      bool
	Severity Severity
	Reason   string
	Signals  []string // human-readable contributing signals
}

// Web-server worker process names that should essentially never author new PHP
// source inside a docroot on their own (legit installs go via packaged updaters
// with a known source anchor — see pkg/source).
var webWorkers = map[string]bool{
	"php-fpm": true, "php": true, "php-cgi": true, "sw-engine-fpm": true,
	"apache2": true, "httpd": true, "nginx": true, "litespeed": true, "lsphp": true,
}

var (
	// Executable-as-PHP extensions (incl. the sneaky ones).
	rxPHPExt = regexp.MustCompile(`(?i)\.(php|php[57]|phtml|phar|pht|inc)$`)
	// A unix time() suffix in a dir/file name — droppers name artifacts after
	// time() at drop moment (archives-1780570449, custom_1780522290).
	rxTimestampName = regexp.MustCompile(`[_-]1[0-9]{9}\b`)
	// Random-hex plugin/dir names (Plugin-8550a10c).
	rxRandHex = regexp.MustCompile(`(?i)\b[a-z]+[-_][0-9a-f]{8}\b`)
	// Typosquats of index.php and friends (lndex, 1ndex, index_, wp-l0gin).
	rxTyposquat = regexp.MustCompile(`(?i)\b(lndex|1ndex|inde\w?x[_0-9]|wp-l0gin|wp_signup|radio\.php|up\.php|0\.php|x\.php|shell\.php|cmd\.php|tmp\.php)\b`)
)

func base(p string) string { return strings.ToLower(path.Base(p)) }

func actorIsWebWorker(s Spec) bool {
	if webWorkers[strings.ToLower(s.ActorComm)] {
		return true
	}
	b := strings.ToLower(path.Base(s.ActorExe))
	for w := range webWorkers {
		if strings.Contains(b, w) {
			return true
		}
	}
	return false
}

// inWebRoot reports whether p is under a typical web document root.
func inWebRoot(p string) bool {
	lp := strings.ToLower(p)
	for _, m := range []string{"/var/www/", "/httpdocs/", "/public_html/", "/wp-content/", "/htdocs/", "/www/"} {
		if strings.Contains(lp, m) {
			return true
		}
	}
	return false
}

// Scan classifies a file-write. A web-server worker writing PHP into a web root
// is the core signal; location and naming heuristics raise severity.
func Scan(s Spec) Verdict {
	if s.Path == "" || !rxPHPExt.MatchString(s.Path) {
		return Verdict{}
	}
	if !inWebRoot(s.Path) {
		return Verdict{}
	}
	web := actorIsWebWorker(s)
	lp := strings.ToLower(s.Path)
	b := base(s.Path)

	var sig []string
	sev := SeverityMedium
	if web {
		sig = append(sig, "web-server worker authored new PHP in a docroot")
		sev = SeverityHigh
	}
	// PHP under uploads/ should never be executable content.
	if strings.Contains(lp, "/uploads/") {
		sig = append(sig, "PHP inside wp-content/uploads (never legitimate)")
		sev = SeverityCritical
	}
	// mu-plugins auto-load with no UI — a favorite persistence spot.
	if strings.Contains(lp, "/mu-plugins/") {
		sig = append(sig, "PHP dropped into mu-plugins (auto-loaded persistence)")
		if sev < SeverityCritical {
			sev = SeverityCritical
		}
	}
	if rxTimestampName.MatchString(s.Path) {
		sig = append(sig, "unix-timestamp-named artifact (drop-time time())")
		if sev < SeverityHigh {
			sev = SeverityHigh
		}
	}
	if rxTyposquat.MatchString(b) {
		sig = append(sig, "webshell-style filename ("+b+")")
		sev = SeverityCritical
	}
	if rxRandHex.MatchString(lp) {
		sig = append(sig, "random-hex plugin/dir name")
		if sev < SeverityHigh {
			sev = SeverityHigh
		}
	}
	if len(sig) == 0 {
		// PHP in a docroot by a non-web actor with no other signal — weak.
		return Verdict{}
	}
	return Verdict{
		Hit:      true,
		Severity: sev,
		Reason:   "suspicious PHP written into web root",
		Signals:  sig,
	}
}
