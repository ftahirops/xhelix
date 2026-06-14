// Package pkglifecycle detects npm/yarn/pnpm lifecycle-script execution
// by reading /proc/<pid>/environ on spawn and propagating the context to
// child processes. Once a process is tagged, every event it generates is
// stamped with install_script=true so CEL rules can gate on it.
//
// This is the foundational primitive for npm supply-chain RAT detection:
// without lineage context, distinguishing a malicious postinstall from a
// legitimate aws-cli call is impossible at the comm/image level.
package pkglifecycle

import (
	"log/slog"
	"sync"
)

// npm environment variable names set by npm/yarn/pnpm in lifecycle hooks.
const (
	envLifecycleEvent = "npm_lifecycle_event"
	envPackageName    = "npm_package_name"
	envConfigRegistry = "npm_config_registry"
)

// NPMContext is the immutable npm lifecycle context for a process lineage.
// All fields are populated from the process environment at spawn time.
type NPMContext struct {
	PackageName    string // e.g. "noon-contracts"
	LifecycleEvent string // e.g. "postinstall", "preinstall", "install"
	Registry       string // e.g. "https://registry.npmjs.org"
}

// Tagger tracks which PIDs are inside an npm lifecycle script, including
// all descendants. It is nil-safe: all methods are no-ops on a nil receiver.
//
// Call TagSpawn on every ebpf.spawn/ebpf.proc event and OnExit on every
// ebpf.exit event. Between spawns, call Tag(pid) to check whether a PID
// is in an npm install-script lineage.
type Tagger struct {
	mu      sync.RWMutex
	pids    map[uint32]*NPMContext
	log     *slog.Logger
	readEnv func(pid uint32) (map[string]string, error)
}

// New creates a Tagger using the platform-specific environ reader
// (reads /proc/<pid>/environ on Linux, no-op stub elsewhere).
func New(log *slog.Logger) *Tagger {
	return &Tagger{
		pids:    make(map[uint32]*NPMContext),
		log:     log,
		readEnv: platformReadEnviron,
	}
}

// newWithReader creates a Tagger with an injectable reader for tests.
func newWithReader(reader func(pid uint32) (map[string]string, error)) *Tagger {
	return &Tagger{
		pids:    make(map[uint32]*NPMContext),
		log:     slog.Default(),
		readEnv: reader,
	}
}

// TagSpawn should be called on every ebpf.spawn / ebpf.proc event.
// It first checks whether the parent is already tagged (inheritance path —
// handles the common case where a postinstall script spawns children that
// don't re-export the lifecycle vars). If not, it reads the process environ
// and records context if npm lifecycle vars are present.
func (t *Tagger) TagSpawn(pid, ppid uint32) {
	if t == nil {
		return
	}

	// Parent inheritance is the hot path: a postinstall script typically
	// spawns node, sh, curl, aws — none of which re-export npm_ vars.
	t.mu.RLock()
	parentCtx := t.pids[ppid]
	t.mu.RUnlock()

	if parentCtx != nil {
		t.mu.Lock()
		t.pids[pid] = parentCtx // immutable pointer — safe to share
		t.mu.Unlock()
		return
	}

	// Slow path: read /proc/<pid>/environ to check if this process itself
	// is a lifecycle script (the root of the lineage).
	env, err := t.readEnv(pid)
	if err != nil || len(env) == 0 {
		return
	}
	lifecycleEvent := env[envLifecycleEvent]
	if lifecycleEvent == "" {
		return
	}

	ctx := &NPMContext{
		PackageName:    env[envPackageName],
		LifecycleEvent: lifecycleEvent,
		Registry:       env[envConfigRegistry],
	}
	if t.log != nil {
		t.log.Info("npm install-script lineage started",
			"pid", pid,
			"package", ctx.PackageName,
			"lifecycle_event", ctx.LifecycleEvent,
		)
	}
	t.mu.Lock()
	t.pids[pid] = ctx
	t.mu.Unlock()
}

// Tag returns the NPMContext for pid if it is inside an npm lifecycle
// script lineage, or nil if it is a normal process.
func (t *Tagger) Tag(pid uint32) *NPMContext {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	ctx := t.pids[pid]
	t.mu.RUnlock()
	return ctx
}

// OnExit removes pid from the tracker. Call on ebpf.exit events to
// prevent unbounded growth. Children already tagged keep their context
// until their own exit.
func (t *Tagger) OnExit(pid uint32) {
	if t == nil {
		return
	}
	t.mu.Lock()
	delete(t.pids, pid)
	t.mu.Unlock()
}
