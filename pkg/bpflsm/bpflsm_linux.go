//go:build linux

package bpflsm

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// loadAndAttach is the Linux-side BPF-LSM load + attach. Called from
// Apply when Probe() returned true + mode is Load or Enforce.
//
// progPath is the path to a compiled BPF object containing the
// xh_lsm_bprm_check program (built from sensors/ebpf/progs/bpflsm.bpf.c
// via `make ebpf-lsm` — see Makefile).
//
// In ModeLoad we load the program but don't attach. Useful to verify
// the program compiles + loads against the host kernel BTF before
// switching to enforce.
//
// In ModeEnforce we additionally call link.AttachLSM to bind it to
// the security_bprm_check hook. After this returns, every subsequent
// execve on the host goes through the deny map check.
func loadAndAttach(progPath string, mode Mode, log *slog.Logger) (*Loader, error) {
	if _, err := os.Stat(progPath); err != nil {
		return nil, fmt.Errorf("bpflsm: program object missing at %s: %w "+
			"(build with `make ebpf-lsm`)", progPath, err)
	}

	spec, err := ebpf.LoadCollectionSpec(progPath)
	if err != nil {
		return nil, fmt.Errorf("bpflsm: load spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("bpflsm: NewCollection: %w", err)
	}

	denyMap := coll.Maps["xh_bpflsm_deny_paths"]
	if denyMap == nil {
		coll.Close()
		return nil, fmt.Errorf("bpflsm: program missing xh_bpflsm_deny_paths map")
	}

	prog := coll.Programs["xh_lsm_bprm_check"]
	if prog == nil {
		coll.Close()
		return nil, fmt.Errorf("bpflsm: program missing xh_lsm_bprm_check function")
	}

	loader := &Loader{
		mode:    mode,
		log:     log,
		closer:  func() error { coll.Close(); return nil },
		updater: makeDenyUpdater(denyMap),
		remover: makeDenyRemover(denyMap),
	}

	if mode == ModeLoad {
		if log != nil {
			log.Info("bpflsm: program loaded (mode=load-only, NOT attached)",
				"program", "xh_lsm_bprm_check",
				"map", "xh_bpflsm_deny_paths")
		}
		return loader, nil
	}

	// ModeEnforce — attach to the LSM hook.
	lsmLink, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("bpflsm: AttachLSM: %w", err)
	}

	// Wrap closer to release the link too.
	origCloser := loader.closer
	loader.closer = func() error {
		_ = lsmLink.Close()
		return origCloser()
	}

	if log != nil {
		log.Info("bpflsm: ENFORCE mode active",
			"program", "xh_lsm_bprm_check",
			"hook", "security_bprm_check",
			"warning", "synchronous execve deny live — verify operator deny map")
	}
	return loader, nil
}

// makeDenyUpdater returns a closure that adds path strings to the
// deny map. Path is NUL-padded to XH_LSM_PATH_MAX (256) to match the
// kernel-side key layout.
func makeDenyUpdater(m *ebpf.Map) func(string) error {
	return func(path string) error {
		const keySize = 256
		if len(path) >= keySize {
			return fmt.Errorf("bpflsm: deny path too long (%d, max %d)", len(path), keySize-1)
		}
		key := make([]byte, keySize)
		copy(key, path)
		val := uint32(1) // 1 = deny
		if err := m.Update(key, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("bpflsm: map update %q: %w", path, err)
		}
		return nil
	}
}

func makeDenyRemover(m *ebpf.Map) func(string) error {
	return func(path string) error {
		const keySize = 256
		if len(path) >= keySize {
			return fmt.Errorf("bpflsm: path too long (%d)", len(path))
		}
		key := make([]byte, keySize)
		copy(key, path)
		if err := m.Delete(key); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil
			}
			return fmt.Errorf("bpflsm: map delete %q: %w", path, err)
		}
		return nil
	}
}
