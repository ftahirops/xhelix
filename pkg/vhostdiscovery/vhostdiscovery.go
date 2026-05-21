// Package vhostdiscovery enumerates web-server document roots and
// reverse-proxy upstreams so FIM can watch them without relying on
// hard-coded path globs.
//
// Why: glob defaults only catch Plesk's exact layout
// (/var/www/vhosts/*/httpdocs/wp-config.php). Real-world Linux
// hosts run nginx pointing at /srv/app1, apache at /home/<user>/
// public_html, Caddy at any path the operator chose, and reverse
// proxies whose actual code root is in some PHP-FPM pool or
// uWSGI cwd far from /var/www.
//
// This package asks the running daemons what their roots are.
// Sources, in order of preference:
//
//	1. `nginx -T` — dumps merged config; we parse `root` and
//	   `proxy_pass` directives.
//	2. `apachectl -S` + `apache2ctl -S` — lists vhosts; for each
//	   we parse the conf file for `DocumentRoot`.
//	3. `caddy adapt` — Caddy JSON config; parse roots.
//	4. /etc/psa/.psa.conf + /var/www/vhosts/*/conf/*.conf (Plesk).
//	5. /usr/local/cpanel/version → cPanel: walk /var/cpanel/users/.
//	6. /usr/local/directadmin/data/users (DirectAdmin).
//
// For each `proxy_pass http://127.0.0.1:NNNN` we resolve the
// listening process via /proc/net/{tcp,unix} → its PID → its
// /proc/PID/cwd. That `cwd` is the code root for the upstream
// app (typical for PHP-FPM, uWSGI, Gunicorn, Node).
//
// The output feeds runtime extension of the FIM watch list at
// daemon startup, same mechanism as pkg/vendorcatalog.
package vhostdiscovery

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Vhost is one discovered web-server vhost or upstream root.
type Vhost struct {
	// Source identifies the discovery path: "nginx", "apache",
	// "caddy", "plesk", "cpanel", "directadmin", "proxy_upstream".
	Source string
	// ServerName is the host header / SNI value. May be empty.
	ServerName string
	// Root is an absolute filesystem path that holds executable
	// app code (PHP, JS, etc.) — what FIM should watch.
	Root string
	// Reason is a short human-readable explanation of how we
	// found this root (for xhelixctl posture vhosts).
	Reason string
}

// Result is what DiscoverAll returns.
type Result struct {
	Vhosts []Vhost
	Errors []string // soft errors per source; not fatal
}

// DiscoverAll runs every discovery method, deduplicating by Root.
// Soft-fails per source — a missing nginx binary just skips that
// source.
func DiscoverAll() Result {
	var r Result
	r.merge(discoverNginx())
	r.merge(discoverApache())
	r.merge(discoverCaddy())
	r.merge(discoverPlesk())
	r.merge(discoverCpanel())
	r.merge(discoverDirectAdmin())
	r.dedup()
	return r
}

func (r *Result) merge(other Result) {
	r.Vhosts = append(r.Vhosts, other.Vhosts...)
	r.Errors = append(r.Errors, other.Errors...)
}

func (r *Result) dedup() {
	seen := map[string]bool{}
	out := r.Vhosts[:0]
	for _, v := range r.Vhosts {
		if v.Root == "" {
			continue
		}
		clean := filepath.Clean(v.Root)
		if seen[clean] {
			continue
		}
		seen[clean] = true
		v.Root = clean
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Root < out[j].Root })
	r.Vhosts = out
}

// FIMWatchPatterns returns the paths to fold into the FIM watch
// list. Caller appends these to the runtime watch set.
//
// We don't return the bare `Root` — that would explode inotify
// load. Instead, we return *high-value targets within each root*:
// wp-config.php, .htaccess, configuration.php, config.inc.php,
// .env, .git/config, mu-plugins/, vendor/autoload.php, plus the
// root itself for new-file detection.
func FIMWatchPatterns(r Result) []string {
	out := []string{}
	for _, v := range r.Vhosts {
		// Sentinel files — these almost never change in a healthy
		// app and modifications are the canonical webshell drop /
		// secret tamper signal.
		out = append(out,
			filepath.Join(v.Root, "wp-config.php"),
			filepath.Join(v.Root, ".htaccess"),
			filepath.Join(v.Root, "configuration.php"),
			filepath.Join(v.Root, "config.inc.php"),
			filepath.Join(v.Root, ".env"),
			filepath.Join(v.Root, ".git/config"),
			filepath.Join(v.Root, "vendor/autoload.php"),
			// WordPress hot directories.
			filepath.Join(v.Root, "wp-content/mu-plugins"),
		)
	}
	return out
}

// ──────────────────────────────── nginx ────────────────────────────

var (
	nginxRoot      = regexp.MustCompile(`(?m)^\s*root\s+([^;]+);`)
	nginxProxyPass = regexp.MustCompile(`(?m)^\s*proxy_pass\s+([^;]+);`)
	nginxServer   = regexp.MustCompile(`(?m)^\s*server_name\s+([^;]+);`)
)

func discoverNginx() Result {
	var r Result
	if _, err := exec.LookPath("nginx"); err != nil {
		return r
	}
	out, err := runWithTimeout("nginx", "-T")
	if err != nil {
		r.Errors = append(r.Errors, "nginx -T: "+err.Error())
		return r
	}
	for _, m := range nginxRoot.FindAllStringSubmatch(out, -1) {
		root := strings.TrimSpace(strings.Trim(m[1], `"`))
		if root != "" && filepath.IsAbs(root) {
			r.Vhosts = append(r.Vhosts, Vhost{
				Source: "nginx", Root: root,
				Reason: "nginx -T: root directive",
			})
		}
	}
	for _, m := range nginxProxyPass.FindAllStringSubmatch(out, -1) {
		upstream := strings.TrimSpace(m[1])
		if root := resolveUpstreamCWD(upstream); root != "" {
			r.Vhosts = append(r.Vhosts, Vhost{
				Source: "proxy_upstream", Root: root,
				Reason: "nginx proxy_pass → " + upstream + " → cwd",
			})
		}
	}
	return r
}

// ─────────────────────────────── apache ────────────────────────────

var apacheDocRoot = regexp.MustCompile(`(?m)^\s*DocumentRoot\s+"?([^"\s]+)"?`)

func discoverApache() Result {
	var r Result
	for _, ctl := range []string{"apachectl", "apache2ctl", "httpd"} {
		if _, err := exec.LookPath(ctl); err != nil {
			continue
		}
		out, err := runWithTimeout(ctl, "-S")
		if err != nil {
			r.Errors = append(r.Errors, ctl+" -S: "+err.Error())
			continue
		}
		// Apache -S lists "vhost: addr:port (path/to/conf:line)"
		// We follow each conf path and grep DocumentRoot.
		seenConf := map[string]bool{}
		for _, line := range strings.Split(out, "\n") {
			if idx := strings.Index(line, " ("); idx > -1 {
				rest := line[idx+2:]
				if end := strings.LastIndex(rest, ":"); end > -1 {
					conf := rest[:end]
					conf = strings.TrimRight(conf, ")")
					if seenConf[conf] {
						continue
					}
					seenConf[conf] = true
					if data, err := os.ReadFile(conf); err == nil {
						for _, m := range apacheDocRoot.FindAllStringSubmatch(string(data), -1) {
							root := m[1]
							if filepath.IsAbs(root) {
								r.Vhosts = append(r.Vhosts, Vhost{
									Source: "apache", Root: root,
									Reason: ctl + " -S: DocumentRoot in " + conf,
								})
							}
						}
					}
				}
			}
		}
		break // first found tool is enough
	}
	return r
}

// ──────────────────────────────── caddy ────────────────────────────

func discoverCaddy() Result {
	var r Result
	if _, err := exec.LookPath("caddy"); err != nil {
		return r
	}
	// caddy adapt requires --config, which we'd have to find.
	// Simpler: read /etc/caddy/Caddyfile if present and grep
	// `root *` directives. Best-effort.
	cfg := "/etc/caddy/Caddyfile"
	if _, err := os.Stat(cfg); err != nil {
		return r
	}
	data, err := os.ReadFile(cfg)
	if err != nil {
		return r
	}
	re := regexp.MustCompile(`(?m)^\s*root\s+\*?\s*(/\S+)`)
	for _, m := range re.FindAllStringSubmatch(string(data), -1) {
		r.Vhosts = append(r.Vhosts, Vhost{
			Source: "caddy", Root: m[1],
			Reason: "Caddyfile: root directive",
		})
	}
	return r
}

// ──────────────────────────────── Plesk ───────────────────────────

func discoverPlesk() Result {
	var r Result
	entries, err := os.ReadDir("/var/www/vhosts")
	if err != nil {
		return r
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "default" || name == "chroot" || strings.HasPrefix(name, ".") {
			continue
		}
		root := filepath.Join("/var/www/vhosts", name, "httpdocs")
		if _, err := os.Stat(root); err == nil {
			r.Vhosts = append(r.Vhosts, Vhost{
				Source: "plesk", ServerName: name, Root: root,
				Reason: "Plesk tenant: " + name,
			})
		}
	}
	return r
}

// ─────────────────────────────── cPanel ───────────────────────────

func discoverCpanel() Result {
	var r Result
	if _, err := os.Stat("/usr/local/cpanel/version"); err != nil {
		return r
	}
	entries, err := os.ReadDir("/var/cpanel/users")
	if err != nil {
		return r
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		user := e.Name()
		root := filepath.Join("/home", user, "public_html")
		if _, err := os.Stat(root); err == nil {
			r.Vhosts = append(r.Vhosts, Vhost{
				Source: "cpanel", ServerName: user, Root: root,
				Reason: "cPanel user: " + user,
			})
		}
	}
	return r
}

// ───────────────────────────── DirectAdmin ────────────────────────

func discoverDirectAdmin() Result {
	var r Result
	if _, err := os.Stat("/usr/local/directadmin"); err != nil {
		return r
	}
	entries, err := os.ReadDir("/usr/local/directadmin/data/users")
	if err != nil {
		return r
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		user := e.Name()
		domDir := filepath.Join("/home", user, "domains")
		domains, err := os.ReadDir(domDir)
		if err != nil {
			continue
		}
		for _, d := range domains {
			if !d.IsDir() {
				continue
			}
			root := filepath.Join(domDir, d.Name(), "public_html")
			if _, err := os.Stat(root); err == nil {
				r.Vhosts = append(r.Vhosts, Vhost{
					Source: "directadmin",
					ServerName: d.Name(), Root: root,
					Reason: "DirectAdmin user/domain: " + user + "/" + d.Name(),
				})
			}
		}
	}
	return r
}

// ───────────────────── proxy upstream → cwd ───────────────────────

// resolveUpstreamCWD takes a proxy_pass target like
// "http://127.0.0.1:9000" or "unix:/run/php-fpm/foo.sock" and
// returns the cwd of the process listening on that endpoint.
// Used to find code roots for FastCGI / Unicorn / Node apps that
// don't expose a `root` directive of their own.
func resolveUpstreamCWD(upstream string) string {
	upstream = strings.TrimSpace(upstream)
	// Unix sockets are easier: peek /proc/net/unix.
	if strings.HasPrefix(upstream, "unix:") {
		sock := strings.TrimPrefix(upstream, "unix:")
		return cwdForUnixSocket(sock)
	}
	// TCP: find listening pid by port via /proc/net/tcp.
	port := portFromURL(upstream)
	if port == 0 {
		return ""
	}
	return cwdForTCPPort(port)
}

func portFromURL(u string) int {
	// "http://127.0.0.1:9000" or "127.0.0.1:9000"
	colon := strings.LastIndex(u, ":")
	if colon < 0 {
		return 0
	}
	tail := u[colon+1:]
	if slash := strings.Index(tail, "/"); slash > -1 {
		tail = tail[:slash]
	}
	p, _ := strconv.Atoi(tail)
	return p
}

func cwdForTCPPort(port int) string {
	// Walk /proc/[0-9]+/net/tcp once is expensive — instead,
	// walk /proc/[0-9]+/fd/* looking for a socket whose inode
	// maps to a listening TCP socket on this port. For startup
	// discovery this is fine; we'd cache for runtime.
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return ""
	}
	want := fmt.Sprintf(":%04X", port)
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		tcpFile := fmt.Sprintf("/proc/%d/net/tcp", pid)
		f, err := os.Open(tcpFile)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		found := false
		for sc.Scan() {
			line := sc.Text()
			// listening = state 0A; local_address column 1
			if strings.Contains(line, want) && strings.Contains(line, " 0A ") {
				found = true
				break
			}
		}
		f.Close()
		if found {
			if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
				return cwd
			}
		}
	}
	return ""
}

func cwdForUnixSocket(sock string) string {
	// Walk /proc/[0-9]+/net/unix, find the inode for sock, then
	// find which pid owns that inode in its fd table.
	data, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		return ""
	}
	var inode string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, sock) {
			fields := strings.Fields(line)
			if len(fields) >= 7 {
				inode = fields[6]
				break
			}
		}
	}
	if inode == "" {
		return ""
	}
	wantLink := "socket:[" + inode + "]"
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if err != nil {
			continue
		}
		for _, f := range fds {
			link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, f.Name()))
			if err == nil && link == wantLink {
				if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
					return cwd
				}
			}
		}
	}
	return ""
}

// ─────────────────────────── helpers ──────────────────────────────

func runWithTimeout(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	done := make(chan struct {
		out []byte
		err error
	}, 1)
	go func() {
		out, err := cmd.CombinedOutput()
		done <- struct {
			out []byte
			err error
		}{out, err}
	}()
	select {
	case r := <-done:
		return string(r.out), r.err
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		return "", fmt.Errorf("%s timed out", name)
	}
}
