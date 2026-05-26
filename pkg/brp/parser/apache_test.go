package brpparser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApache_Static(t *testing.T) {
	conf := `
Listen 80
LoadModule dir_module modules/mod_dir.so
<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
    ErrorLog /var/log/apache2/error.log
    CustomLog /var/log/apache2/access.log combined
</VirtualHost>`
	path := writeTmp(t, "httpd.conf", conf)
	b, k, err := ParseApache(path)
	if err != nil {
		t.Fatalf("ParseApache: %v", err)
	}
	if b.Role != "apache-static" {
		t.Errorf("Role = %q, want apache-static", b.Role)
	}
	if !containsInt(b.ListenPorts, 80) {
		t.Errorf("ListenPorts missing 80: %v", b.ListenPorts)
	}
	if !contains(b.ReadRoots, "/var/www/html/") {
		t.Errorf("ReadRoots missing /var/www/html/: %v", b.ReadRoots)
	}
	if k.App != "apache" || k.Role != "apache-static" {
		t.Errorf("ProfileKey wrong: %+v", k)
	}
}

func TestApache_ReverseProxy(t *testing.T) {
	conf := `
Listen 443
LoadModule ssl_module modules/mod_ssl.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/ex.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/ex.com/privkey.pem
    ProxyPass /api http://backend:8080/api
    ProxyPassReverse /api http://backend:8080/api
</VirtualHost>`
	path := writeTmp(t, "httpd.conf", conf)
	b, _, _ := ParseApache(path)
	if b.Role != "apache-reverse-proxy" {
		t.Errorf("Role = %q, want apache-reverse-proxy", b.Role)
	}
	if !containsAll(b.Features, "tls", "proxy_pass") {
		t.Errorf("Features missing tls/proxy_pass: %v", b.Features)
	}
	if !contains(b.UpstreamHosts, "backend:8080") {
		t.Errorf("UpstreamHosts missing backend:8080: %v", b.UpstreamHosts)
	}
	if !contains(b.ReadRoots, "/etc/letsencrypt/live/ex.com/") {
		t.Errorf("ReadRoots missing letsencrypt dir: %v", b.ReadRoots)
	}
}

func TestApache_FastCGI_PhpFpm(t *testing.T) {
	conf := `
Listen 80
LoadModule php_module modules/libphp.so
<VirtualHost *:80>
    DocumentRoot /var/www/site
    <FilesMatch \.php$>
        SetHandler "proxy:fcgi://127.0.0.1:9000"
    </FilesMatch>
</VirtualHost>`
	path := writeTmp(t, "httpd.conf", conf)
	b, _, _ := ParseApache(path)
	if b.Role != "apache-fastcgi" {
		t.Errorf("Role = %q, want apache-fastcgi", b.Role)
	}
	if !contains(b.UpstreamHosts, "127.0.0.1:9000") {
		t.Errorf("UpstreamHosts missing 127.0.0.1:9000: %v", b.UpstreamHosts)
	}
	if !contains(b.Features, "php") {
		t.Errorf("Features missing php: %v", b.Features)
	}
}

func TestApache_CGI(t *testing.T) {
	conf := `
Listen 80
LoadModule cgid_module modules/mod_cgid.so
ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
<VirtualHost *:80>
    DocumentRoot /var/www
</VirtualHost>`
	path := writeTmp(t, "httpd.conf", conf)
	b, _, _ := ParseApache(path)
	if b.Role != "apache-cgi" {
		t.Errorf("Role = %q, want apache-cgi", b.Role)
	}
	if !contains(b.ExecAllowed, "/usr/lib/cgi-bin/") {
		t.Errorf("ExecAllowed missing cgi-bin: %v", b.ExecAllowed)
	}
}

func TestApache_WSGI(t *testing.T) {
	conf := `
Listen 80
LoadModule wsgi_module modules/mod_wsgi.so
<VirtualHost *:80>
    WSGIScriptAlias / /var/www/app/wsgi.py
</VirtualHost>`
	path := writeTmp(t, "httpd.conf", conf)
	b, _, _ := ParseApache(path)
	if b.Role != "apache-wsgi" {
		t.Errorf("Role = %q, want apache-wsgi", b.Role)
	}
}

func TestApache_HTTP2(t *testing.T) {
	conf := `
Listen 443
LoadModule ssl_module modules/mod_ssl.so
LoadModule http2_module modules/mod_http2.so
Protocols h2 http/1.1
<VirtualHost *:443>
    SSLEngine on
    DocumentRoot /var/www
</VirtualHost>`
	path := writeTmp(t, "httpd.conf", conf)
	b, _, _ := ParseApache(path)
	if !contains(b.Features, "http2") {
		t.Errorf("Features missing http2: %v", b.Features)
	}
	if !contains(b.Features, "tls") {
		t.Errorf("Features missing tls: %v", b.Features)
	}
}

func TestApache_Include(t *testing.T) {
	tmp := t.TempDir()
	vhost := filepath.Join(tmp, "site.conf")
	_ = os.WriteFile(vhost, []byte(`<VirtualHost *:8080>
    DocumentRoot /srv/site
</VirtualHost>`), 0o644)
	main := filepath.Join(tmp, "httpd.conf")
	_ = os.WriteFile(main, []byte(`IncludeOptional `+vhost), 0o644)
	b, _, err := ParseApache(main)
	if err != nil {
		t.Fatalf("ParseApache: %v", err)
	}
	if !containsInt(b.ListenPorts, 8080) {
		t.Errorf("vhost port 8080 missing: %v", b.ListenPorts)
	}
	if !contains(b.ReadRoots, "/srv/site/") {
		t.Errorf("vhost DocumentRoot missing: %v", b.ReadRoots)
	}
}

func TestApache_NonExistentFileError(t *testing.T) {
	_, _, err := ParseApache("/nonexistent/httpd.conf")
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestApache_QuotedAndCommented(t *testing.T) {
	conf := `
# top comment
Listen 80
<VirtualHost *:80>
    # nested comment
    ServerName "weird.example.com"
    DocumentRoot "/var/www/with spaces"
    SetHandler "proxy:fcgi://127.0.0.1:9000"
</VirtualHost>`
	path := writeTmp(t, "httpd.conf", conf)
	b, _, err := ParseApache(path)
	if err != nil {
		t.Fatalf("ParseApache: %v", err)
	}
	if !contains(b.ReadRoots, "/var/www/with spaces/") {
		t.Errorf("quoted DocumentRoot not parsed: %v", b.ReadRoots)
	}
	if !contains(b.UpstreamHosts, "127.0.0.1:9000") {
		t.Errorf("SetHandler proxy:fcgi not parsed: %v", b.UpstreamHosts)
	}
}
