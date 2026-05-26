package brpparser

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// writeTmp writes content to a fresh tmp file and returns the path.
func writeTmp(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestNginx_Static(t *testing.T) {
	conf := `
worker_processes 4;
events { worker_connections 1024; }
http {
    server {
        listen 80;
        server_name example.com;
        root /var/www/example;
        access_log /var/log/nginx/example.log;
    }
}`
	path := writeTmp(t, "nginx.conf", conf)
	b, k, err := ParseNginx(path)
	if err != nil {
		t.Fatalf("ParseNginx: %v", err)
	}
	if b.Role != "nginx-static" {
		t.Errorf("Role = %q, want nginx-static", b.Role)
	}
	if !containsInt(b.ListenPorts, 80) {
		t.Errorf("ListenPorts missing 80: %v", b.ListenPorts)
	}
	if !contains(b.ReadRoots, "/var/www/example/") {
		t.Errorf("ReadRoots missing /var/www/example/: %v", b.ReadRoots)
	}
	if !contains(b.WriteRoots, "/var/log/nginx/") {
		t.Errorf("WriteRoots missing /var/log/nginx/: %v", b.WriteRoots)
	}
	if k.App != "nginx" || k.Role != "nginx-static" {
		t.Errorf("ProfileKey app/role wrong: %+v", k)
	}
	if k.FeatureFingerprint == "" {
		t.Error("FeatureFingerprint should be non-empty")
	}
}

func TestNginx_ReverseProxy(t *testing.T) {
	conf := `
http {
    upstream backend {
        server 10.0.0.1:8080;
        server 10.0.0.2:8080;
    }
    server {
        listen 443 ssl http2;
        ssl_certificate /etc/letsencrypt/live/ex.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/ex.com/privkey.pem;
        location / { proxy_pass http://backend/; }
    }
}`
	path := writeTmp(t, "nginx.conf", conf)
	b, k, _ := ParseNginx(path)
	if b.Role != "nginx-reverse-proxy" {
		t.Errorf("Role = %q, want nginx-reverse-proxy", b.Role)
	}
	if !containsAll(b.Features, "tls", "http2", "proxy_pass") {
		t.Errorf("Features missing tls/http2/proxy_pass: %v", b.Features)
	}
	if !containsInt(b.ListenPorts, 443) {
		t.Errorf("ListenPorts missing 443: %v", b.ListenPorts)
	}
	if !contains(b.UpstreamHosts, "backend") {
		t.Errorf("UpstreamHosts missing 'backend': %v", b.UpstreamHosts)
	}
	if !contains(b.ReadRoots, "/etc/letsencrypt/live/ex.com/") {
		t.Errorf("ReadRoots missing letsencrypt dir: %v", b.ReadRoots)
	}
	if k.FeatureFingerprint == "" {
		t.Error("FeatureFingerprint should be non-empty")
	}
}

func TestNginx_FastCGI(t *testing.T) {
	conf := `
http {
    server {
        listen 80;
        root /var/www/php;
        location ~ \.php$ {
            fastcgi_pass unix:/run/php-fpm.sock;
            include fastcgi_params;
        }
    }
}`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "nginx.conf")
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	// fastcgi_params include is intentionally missing — parser must
	// emit a warning, not abort.
	b, _, _ := ParseNginx(path)
	if b.Role != "nginx-fastcgi" {
		t.Errorf("Role = %q, want nginx-fastcgi", b.Role)
	}
	if !contains(b.UpstreamSockets, "/run/php-fpm.sock") {
		t.Errorf("UpstreamSockets missing /run/php-fpm.sock: %v", b.UpstreamSockets)
	}
	if !contains(b.Features, "fastcgi_pass") {
		t.Errorf("Features missing fastcgi_pass: %v", b.Features)
	}
	if len(b.ParseWarnings) == 0 {
		t.Errorf("expected a warning for missing fastcgi_params include")
	}
	if !contains(b.Features, "regex_location") {
		t.Errorf("expected regex_location feature, got %v", b.Features)
	}
}

func TestNginx_Lua(t *testing.T) {
	conf := `
http {
    lua_package_path "/usr/lib/lua/?.lua;;";
    server {
        listen 80;
        location / { content_by_lua_file /etc/nginx/lua/handler.lua; }
    }
}`
	path := writeTmp(t, "nginx.conf", conf)
	b, _, _ := ParseNginx(path)
	if b.Role != "nginx-lua" {
		t.Errorf("Role = %q, want nginx-lua (highest specificity)", b.Role)
	}
	if !contains(b.Modules, "ngx_http_lua_module") {
		t.Errorf("Modules missing ngx_http_lua_module: %v", b.Modules)
	}
}

func TestNginx_NJS(t *testing.T) {
	conf := `
http {
    js_import main.js;
    server {
        listen 80;
        location /api { js_content main.handle; }
    }
}`
	path := writeTmp(t, "nginx.conf", conf)
	b, _, _ := ParseNginx(path)
	if b.Role != "nginx-njs" {
		t.Errorf("Role = %q, want nginx-njs", b.Role)
	}
}

func TestNginx_GrpcProxy(t *testing.T) {
	conf := `
http {
    server {
        listen 50051 http2;
        location / { grpc_pass grpc://backend:50051; }
    }
}`
	path := writeTmp(t, "nginx.conf", conf)
	b, _, _ := ParseNginx(path)
	if b.Role != "nginx-grpc-proxy" {
		t.Errorf("Role = %q, want nginx-grpc-proxy", b.Role)
	}
	if !contains(b.UpstreamHosts, "backend:50051") {
		t.Errorf("UpstreamHosts missing backend:50051: %v", b.UpstreamHosts)
	}
}

func TestNginx_Include(t *testing.T) {
	tmp := t.TempDir()
	included := filepath.Join(tmp, "site.conf")
	if err := os.WriteFile(included, []byte(`server { listen 8080; root /srv; }`), 0o644); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(tmp, "nginx.conf")
	if err := os.WriteFile(main, []byte(`http { include `+included+`; }`), 0o644); err != nil {
		t.Fatal(err)
	}
	b, _, err := ParseNginx(main)
	if err != nil {
		t.Fatalf("ParseNginx: %v", err)
	}
	if !containsInt(b.ListenPorts, 8080) {
		t.Errorf("included file's listen 8080 missing: %v", b.ListenPorts)
	}
	if !contains(b.ReadRoots, "/srv/") {
		t.Errorf("included file's root missing: %v", b.ReadRoots)
	}
}

func TestNginx_QuotedStringsAndComments(t *testing.T) {
	conf := `
# top comment
http {
    # nested comment
    server {
        listen 80;  # trailing
        server_name "weird name with spaces";
        access_log "/var/log/nginx/site one/access.log";
    }
}`
	path := writeTmp(t, "nginx.conf", conf)
	b, _, err := ParseNginx(path)
	if err != nil {
		t.Fatalf("ParseNginx: %v", err)
	}
	if !containsInt(b.ListenPorts, 80) {
		t.Errorf("listen 80 missing: %v", b.ListenPorts)
	}
	// "/var/log/nginx/site one/" — the directory of the quoted log path.
	if !contains(b.WriteRoots, "/var/log/nginx/site one/") {
		t.Errorf("quoted log path not parsed: %v", b.WriteRoots)
	}
}

func TestNginx_LoadModule(t *testing.T) {
	conf := `
load_module modules/ngx_http_brotli_filter_module.so;
load_module modules/ngx_http_brotli_static_module.so;
events {}
http { server { listen 80; root /var/www; } }`
	path := writeTmp(t, "nginx.conf", conf)
	b, _, _ := ParseNginx(path)
	if !contains(b.Modules, "ngx_http_brotli_filter_module.so") ||
		!contains(b.Modules, "ngx_http_brotli_static_module.so") {
		t.Errorf("modules missing: %v", b.Modules)
	}
}

func TestNginx_NonExistentFileError(t *testing.T) {
	_, _, err := ParseNginx("/nonexistent/nginx.conf")
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestNginx_RolePriority_LuaOverFastCGI(t *testing.T) {
	// If config has BOTH lua and fastcgi, Lua wins (more specific).
	conf := `
http {
    lua_package_path "/p/?.lua;;";
    server {
        listen 80;
        location / {
            content_by_lua_file /h.lua;
            fastcgi_pass unix:/sock;
        }
    }
}`
	path := writeTmp(t, "nginx.conf", conf)
	b, _, _ := ParseNginx(path)
	if b.Role != "nginx-lua" {
		t.Errorf("Lua should win over FastCGI: got %q", b.Role)
	}
}

func TestNginx_FeatureFingerprint_Stable(t *testing.T) {
	conf := `
http {
    server {
        listen 80;
        listen 443 ssl http2;
        location / { proxy_pass http://backend/; }
    }
}`
	path := writeTmp(t, "nginx.conf", conf)
	b1, _, _ := ParseNginx(path)
	b2, _, _ := ParseNginx(path)
	if b1.FeatureFingerprint() != b2.FeatureFingerprint() {
		t.Errorf("fingerprint not stable: %q vs %q",
			b1.FeatureFingerprint(), b2.FeatureFingerprint())
	}
	// Differing-feature configs should hash differently.
	conf2 := `http { server { listen 80; root /var/www; } }`
	path2 := writeTmp(t, "nginx2.conf", conf2)
	b3, _, _ := ParseNginx(path2)
	if b1.FeatureFingerprint() == b3.FeatureFingerprint() {
		t.Error("different features should produce different fingerprints")
	}
}

// ─────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
func containsAll(haystack []string, needles ...string) bool {
	for _, n := range needles {
		if !contains(haystack, n) {
			return false
		}
	}
	return true
}
func containsInt(haystack []int, needle int) bool {
	idx := sort.SearchInts(haystack, needle)
	return idx < len(haystack) && haystack[idx] == needle
}

// Smoke-print helpers (left here for debugging during development).
var _ = strings.Join
