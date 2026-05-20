package contracts

import (
	"fmt"

	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

// builtinNginx returns the default ServiceContract for nginx in the
// given role. Conservative allowlists; deny-list always includes the
// NeverLearnable* baselines.
func builtinNginx(role protectedsvc.ServiceRole) (protectedsvc.ServiceContract, error) {
	switch role {
	case protectedsvc.RoleStatic:
		return nginxStatic(), nil
	case protectedsvc.RoleReverseProxy:
		return nginxReverseProxy(), nil
	case protectedsvc.RoleFastCGI:
		return nginxFastCGI(), nil
	}
	return protectedsvc.ServiceContract{},
		fmt.Errorf("%w: nginx does not support role %q", ErrUnsupportedRole, role)
}

// nginxStatic — nginx serving only static files. Tightest contract.
//
// Expectations:
//   - No outbound (except DNS for resolver directives, if configured)
//   - No interpreter / shell exec
//   - Writes only to log/cache/temp/run
//   - No listening UNIX sockets to other services
func nginxStatic() protectedsvc.ServiceContract {
	return protectedsvc.ServiceContract{
		DenyExecPaths:        append([]string(nil), NeverLearnableExec...),
		AllowExecPaths:       nil, // strict — exec nothing
		WriteRoots:           defaultNginxWriteRoots(),
		ReadSensitiveRoots:   nil,
		UpstreamCIDRs:        nil, // no upstreams in static mode
		DNSResolvers:         nil,
		UnixSockets:          nil,
		ListenPorts:          []uint16{80, 443},
		DenySyscalls:         append([]string(nil), NeverLearnableSyscalls...),
		DenyMemoryPrimitives: append([]protectedsvc.MemoryPrimitive(nil), NeverLearnableMemory...),
		StrictReadOnly:       true,
	}
}

// nginxReverseProxy — nginx forwarding to upstream HTTP backends.
//
// Expectations:
//   - Outbound only to configured upstream_cidrs (operator declares)
//   - No interpreter / shell exec
//   - Writes only to log/cache/temp/run
//   - Built-in leaves UpstreamCIDRs empty — operator MUST declare or
//     the service can't reach upstreams (fail-closed)
func nginxReverseProxy() protectedsvc.ServiceContract {
	return protectedsvc.ServiceContract{
		DenyExecPaths:        append([]string(nil), NeverLearnableExec...),
		AllowExecPaths:       nil,
		WriteRoots:           defaultNginxWriteRoots(),
		ReadSensitiveRoots:   nil,
		UpstreamCIDRs:        nil, // operator declares
		DNSResolvers:         nil,
		UnixSockets:          nil,
		ListenPorts:          []uint16{80, 443},
		DenySyscalls:         append([]string(nil), NeverLearnableSyscalls...),
		DenyMemoryPrimitives: append([]protectedsvc.MemoryPrimitive(nil), NeverLearnableMemory...),
		StrictReadOnly:       true,
	}
}

// nginxFastCGI — nginx talking to php-fpm or similar via UNIX socket.
//
// Expectations:
//   - Local UNIX socket to fastcgi backend (typical: /run/php/php-fpm.sock)
//   - No outbound IP traffic
//   - No interpreter / shell exec (PHP is invoked over the socket,
//     never via execve from nginx directly)
//   - Writes only to log/cache/temp/run
func nginxFastCGI() protectedsvc.ServiceContract {
	return protectedsvc.ServiceContract{
		DenyExecPaths:  append([]string(nil), NeverLearnableExec...),
		AllowExecPaths: nil,
		WriteRoots:     defaultNginxWriteRoots(),
		UnixSockets: []string{
			"/run/php/php-fpm.sock",
			"/var/run/php/php-fpm.sock",
		},
		ListenPorts:          []uint16{80, 443},
		DenySyscalls:         append([]string(nil), NeverLearnableSyscalls...),
		DenyMemoryPrimitives: append([]protectedsvc.MemoryPrimitive(nil), NeverLearnableMemory...),
		StrictReadOnly:       true,
	}
}

// defaultNginxWriteRoots — paths nginx may write to in any role.
// Matches stock Debian/Ubuntu/RHEL nginx layouts.
func defaultNginxWriteRoots() []string {
	return []string{
		"/var/log/nginx",
		"/var/cache/nginx",
		"/var/lib/nginx",
		"/run/nginx",
		"/tmp", // worker tempfiles only; AppArmor can tighten if needed
	}
}
