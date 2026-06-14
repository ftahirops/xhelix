// Package servicerole classifies a process into a coarse service role
// (web/database/cache/...) for grouping egress traffic. It is a pure,
// table-driven heuristic: a known-binary basename map is the primary
// signal, with the appident Kind hint and the process's listening port
// as weaker fallbacks. Unknown processes are RoleOther — never guessed.
package servicerole

import (
	"path/filepath"
	"strings"
)

type Role string

const (
	RoleWeb      Role = "web"
	RoleDatabase Role = "database"
	RoleCache    Role = "cache"
	RoleBroker   Role = "broker"
	RoleProxy    Role = "proxy"
	RoleMail     Role = "mail"
	RoleDNS      Role = "dns"
	RoleSSH      Role = "ssh"
	RoleOther    Role = "other"
)

var byBinary = map[string]Role{
	"nginx": RoleWeb, "apache2": RoleWeb, "httpd": RoleWeb, "caddy": RoleWeb,
	"lighttpd": RoleWeb, "traefik": RoleWeb, "node": RoleWeb, "gunicorn": RoleWeb, "uwsgi": RoleWeb,
	"mysqld": RoleDatabase, "mariadbd": RoleDatabase, "postgres": RoleDatabase,
	"mongod": RoleDatabase, "clickhouse-serv": RoleDatabase, "influxd": RoleDatabase,
	"redis-server": RoleCache, "memcached": RoleCache,
	"beam.smp": RoleBroker, "rabbitmq-server": RoleBroker, "kafka": RoleBroker, "nats-server": RoleBroker,
	"haproxy": RoleProxy, "envoy": RoleProxy, "squid": RoleProxy,
	"master": RoleMail, "smtpd": RoleMail, "dovecot": RoleMail, "exim4": RoleMail,
	"named": RoleDNS, "unbound": RoleDNS, "dnsmasq": RoleDNS, "coredns": RoleDNS,
	"sshd": RoleSSH,
}

var byPort = map[uint16]Role{
	80: RoleWeb, 443: RoleWeb, 8080: RoleWeb, 8443: RoleWeb,
	3306: RoleDatabase, 5432: RoleDatabase, 27017: RoleDatabase,
	6379: RoleCache, 11211: RoleCache,
	5672: RoleBroker, 9092: RoleBroker,
	25: RoleMail, 587: RoleMail, 993: RoleMail,
	53: RoleDNS, 22: RoleSSH,
}

// Classify returns the service role for a process. binaryPath/comm identify
// the binary; appKind is the appident Kind hint ("web"/"service"/...);
// listenPort is the process's listening port (0 if unknown / not a server).
func Classify(binaryPath, comm, appKind string, listenPort uint16) Role {
	base := comm
	if binaryPath != "" {
		base = filepath.Base(binaryPath)
	}
	if r, ok := byBinary[base]; ok {
		return r
	}
	if comm != "" {
		if r, ok := byBinary[comm]; ok {
			return r
		}
	}
	if strings.EqualFold(appKind, "web") {
		return RoleWeb
	}
	if listenPort != 0 {
		if r, ok := byPort[listenPort]; ok {
			return r
		}
	}
	return RoleOther
}
