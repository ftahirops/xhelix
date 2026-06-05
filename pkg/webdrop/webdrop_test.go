package webdrop

import "testing"

// Replays the real 2026-06 newbikebox.bikeboxmt.com intrusion file drops to prove
// the detector fires on the actual attack, and stays quiet on legitimate writes.
func TestNewbikeboxBreachReplay(t *testing.T) {
	const root = "/var/www/vhosts/newbikebox.bikeboxmt.com/httpdocs"
	php := Spec{ActorComm: "php-fpm", ActorExe: "/opt/plesk/php/8.3/sbin/php-fpm"}

	hits := []struct {
		name string
		path string
		min  Severity
	}{
		{"typosquat webshell lndex.php", root + "/wp-content/themes/archives-1780570449/lndex.php", SeverityCritical},
		{"timestamp theme dropper", root + "/wp-content/themes/archives-1780570449/inc/custom_functions_1780570449.php", SeverityHigh},
		{"timestamp plugin custom_1780522290", root + "/wp-content/plugins/custom_1780522290/x.php", SeverityHigh},
		{"random-hex plugin", root + "/wp-content/plugins/Plugin-8550a10c/index.php", SeverityHigh},
		{"mu-plugin persistence", root + "/wp-content/mu-plugins/01-mu.php", SeverityCritical},
		{"tmp.php stage-2", root + "/wp-content/themes/archives-1780570449/tmp.php", SeverityCritical},
		{"php in uploads", root + "/wp-content/uploads/2026/06/up.php", SeverityCritical},
	}
	for _, h := range hits {
		v := Scan(Spec{ActorComm: php.ActorComm, ActorExe: php.ActorExe, Path: h.path})
		if !v.Hit {
			t.Errorf("MISS: %s (%s) — should have fired", h.name, h.path)
			continue
		}
		if v.Severity < h.min {
			t.Errorf("%s: severity %s < expected %s (signals=%v)", h.name, v.Severity, h.min, v.Signals)
		}
	}
}

func TestBenignWritesQuiet(t *testing.T) {
	benign := []Spec{
		// Legit uploads — not executable.
		{"php-fpm", "/x/php-fpm", "/var/www/vhosts/site/httpdocs/wp-content/uploads/2026/06/photo.jpg"},
		// Cache file, not php.
		{"php-fpm", "/x/php-fpm", "/var/www/vhosts/site/httpdocs/wp-content/cache/page.html"},
		// PHP, but outside any web root (a CLI tool writing to /tmp).
		{"php", "/usr/bin/php", "/tmp/build/generated.php"},
		// Non-web actor writing PHP in a docroot with no other signal (e.g. an
		// admin deploy via rsync) — intentionally NOT flagged here; that's the
		// source-anchor layer's job, not a blind FP.
		{"rsync", "/usr/bin/rsync", "/var/www/vhosts/site/httpdocs/wp-content/plugins/akismet/akismet.php"},
	}
	for _, s := range benign {
		if v := Scan(s); v.Hit {
			t.Errorf("FALSE POSITIVE on benign write %q (signals=%v)", s.Path, v.Signals)
		}
	}
}

// A web worker writing an ordinary-looking plugin php still fires (medium/high) —
// because a php-fpm worker authoring its own new PHP source is itself the signal.
func TestWebWorkerOrdinaryPHPStillFlags(t *testing.T) {
	v := Scan(Spec{ActorComm: "php-fpm", ActorExe: "/x/php-fpm",
		Path: "/var/www/vhosts/site/httpdocs/wp-content/plugins/manage/manage.php"})
	if !v.Hit || v.Severity < SeverityHigh {
		t.Fatalf("web-worker PHP write should be >=high, got hit=%v sev=%s", v.Hit, v.Severity)
	}
}
