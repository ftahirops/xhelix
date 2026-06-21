package contracts

import (
	"fmt"

	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

// builtinMysql / builtinPostgres / builtinRedis return the default
// ServiceContract for a database / cache daemon. These daemons have no
// legitimate reason to exec a shell, interpreter, downloader, or recon
// tool — so the full NeverLearnable* deny floor applies with an empty
// allow-list (StrictReadOnly: exec nothing, write only to data/log dirs).
//
// NOTE: php-fpm and sshd are deliberately NOT modeled here — php legitimately
// shells out for some apps (a BRP-layer decision) and sshd legitimately spawns
// login shells. See docs/.../2026-06-21-sp1a1-... "Deferred".

func builtinMysql(role protectedsvc.ServiceRole) (protectedsvc.ServiceContract, error) {
	if role != protectedsvc.RoleDatabase {
		return protectedsvc.ServiceContract{},
			fmt.Errorf("%w: mysql does not support role %q", ErrUnsupportedRole, role)
	}
	return daemonContract([]string{
		"/var/lib/mysql", "/var/log/mysql", "/var/run/mysqld", "/run/mysqld", "/tmp",
	}, []uint16{3306}), nil
}

func builtinPostgres(role protectedsvc.ServiceRole) (protectedsvc.ServiceContract, error) {
	if role != protectedsvc.RoleDatabase {
		return protectedsvc.ServiceContract{},
			fmt.Errorf("%w: postgres does not support role %q", ErrUnsupportedRole, role)
	}
	return daemonContract([]string{
		"/var/lib/postgresql", "/var/log/postgresql", "/var/run/postgresql", "/run/postgresql", "/tmp",
	}, []uint16{5432}), nil
}

func builtinRedis(role protectedsvc.ServiceRole) (protectedsvc.ServiceContract, error) {
	if role != protectedsvc.RoleCache {
		return protectedsvc.ServiceContract{},
			fmt.Errorf("%w: redis does not support role %q", ErrUnsupportedRole, role)
	}
	return daemonContract([]string{
		"/var/lib/redis", "/var/log/redis", "/run/redis", "/tmp",
	}, []uint16{6379}), nil
}

// daemonContract is the shared skeleton for a single-purpose daemon that
// execs nothing and writes only to its data/log/run roots.
func daemonContract(writeRoots []string, ports []uint16) protectedsvc.ServiceContract {
	return protectedsvc.ServiceContract{
		DenyExecPaths:        append([]string(nil), NeverLearnableExec...),
		AllowExecPaths:       nil,
		WriteRoots:           writeRoots,
		ListenPorts:          ports,
		DenySyscalls:         append([]string(nil), NeverLearnableSyscalls...),
		DenyMemoryPrimitives: append([]protectedsvc.MemoryPrimitive(nil), NeverLearnableMemory...),
		StrictReadOnly:       true,
	}
}
