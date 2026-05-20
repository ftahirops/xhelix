package contracts

import (
	"fmt"

	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

// builtinApache returns the default ServiceContract for apache in
// the given role.
func builtinApache(role protectedsvc.ServiceRole) (protectedsvc.ServiceContract, error) {
	switch role {
	case protectedsvc.RoleStatic:
		return apacheStatic(), nil
	case protectedsvc.RoleReverseProxy:
		return apacheReverseProxy(), nil
	case protectedsvc.RolePHPModule:
		return apachePHPModule(), nil
	}
	return protectedsvc.ServiceContract{},
		fmt.Errorf("%w: apache does not support role %q", ErrUnsupportedRole, role)
}

// apacheStatic — apache serving only static files.
func apacheStatic() protectedsvc.ServiceContract {
	return protectedsvc.ServiceContract{
		DenyExecPaths:        append([]string(nil), NeverLearnableExec...),
		WriteRoots:           defaultApacheWriteRoots(),
		ListenPorts:          []uint16{80, 443},
		DenySyscalls:         append([]string(nil), NeverLearnableSyscalls...),
		DenyMemoryPrimitives: append([]protectedsvc.MemoryPrimitive(nil), NeverLearnableMemory...),
		StrictReadOnly:       true,
	}
}

// apacheReverseProxy — apache as a reverse proxy.
func apacheReverseProxy() protectedsvc.ServiceContract {
	return protectedsvc.ServiceContract{
		DenyExecPaths:        append([]string(nil), NeverLearnableExec...),
		WriteRoots:           defaultApacheWriteRoots(),
		ListenPorts:          []uint16{80, 443},
		DenySyscalls:         append([]string(nil), NeverLearnableSyscalls...),
		DenyMemoryPrimitives: append([]protectedsvc.MemoryPrimitive(nil), NeverLearnableMemory...),
		StrictReadOnly:       true,
	}
}

// apachePHPModule — apache running PHP via mod_php (in-process).
//
// This role is the trickiest: PHP runs INSIDE the apache process so
// some exec is legitimate (image processing, mail submission, etc.).
// The contract still denies all NeverLearnable paths but operators
// MUST configure AllowExecPaths for any legitimate helpers their app
// needs (and those helpers go through the AppArmor profile too).
//
// Note: legitimate "exec from PHP" is path-controlled — the operator
// is responsible for putting helpers in allowed paths, and AppArmor
// confines what those helpers can do recursively.
func apachePHPModule() protectedsvc.ServiceContract {
	return protectedsvc.ServiceContract{
		DenyExecPaths:  append([]string(nil), NeverLearnableExec...),
		AllowExecPaths: nil, // operator declares per-app
		WriteRoots: append(defaultApacheWriteRoots(),
			// PHP session storage typically lives here.
			"/var/lib/php",
			"/var/lib/php/sessions",
		),
		// PHP module reads more aggressively from app code roots —
		// no read-only enforcement by default in this role.
		ReadSensitiveRoots:   nil,
		DenySyscalls:         append([]string(nil), NeverLearnableSyscalls...),
		DenyMemoryPrimitives: append([]protectedsvc.MemoryPrimitive(nil), NeverLearnableMemory...),
		StrictReadOnly:       false,
	}
}

// defaultApacheWriteRoots — paths apache may write to in any role.
// Matches stock Debian/Ubuntu (apache2) and RHEL (httpd) layouts.
func defaultApacheWriteRoots() []string {
	return []string{
		"/var/log/apache2",
		"/var/log/httpd",
		"/var/cache/apache2",
		"/var/cache/httpd",
		"/var/lib/apache2",
		"/run/apache2",
		"/run/httpd",
		"/tmp",
	}
}
