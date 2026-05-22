// Command c2-sim mimics the multi-stage behaviour of a real Linux
// implant on a compromised host, exercising the Tier-1 deterministic
// signals xhelix is designed to catch. The goal is provable
// detection coverage — for every stage that runs, the expected
// xhelix rule_id is printed so an operator can grep the alert log /
// Slack feed for matches.
//
// Behaviours simulated (all benign — see the safety notes below):
//
//   1. memfd_create + exec from memory          → ebpf.shm_exec / shm.exec
//   2. deleted-binary-running                   → procmem.deleted_binary_running
//   3. honey-decoy file read                    → credbroker.honey_touched
//   4. sealed-credential open from no-contract  → credbroker.unauthentic_open
//   5. RWX anonymous mmap                       → ebpf.rwx_mprotect / mem_mprotect_rwx
//   6. parent-mismatch shell spawn              → parent_mismatch
//   7. cron persistence drop                    → cron_new_unit / user_crontab_modified
//   8. outbound to TEST-NET-1 (RFC5737 reserved) → exfil shape; egress observer flag
//
// SAFETY:
//
//   * Every behaviour exits on completion. No persistent process.
//   * Network exfil only targets RFC5737 (192.0.2.x, 198.51.100.x,
//     203.0.113.x) — by IETF standard these never route, so no real
//     traffic leaves the host.
//   * Cron drop is to /etc/cron.d/xhelix-c2sim-<ts>; removed at exit.
//   * RWX mmap is anonymous + private; never written to disk.
//   * No credential exfiltration to real targets.
//
// Run with `--stages all` for the full exercise, or `--stages 1,3,5`
// to pick individual ones. Each stage prints:
//
//   STAGE n: <name>
//   expected: <rule_id list>
//   [...actions...]
//   STAGE n: done
//
// Compare against `xhelixctl alerts --since 5m` and your Slack feed.
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type stageFn func() error

type stageDef struct {
	num      int
	name     string
	expected []string
	fn       stageFn
}

func main() {
	flagStages := flag.String("stages", "all", "comma-separated stage numbers (1-8) or 'all'")
	flagDryRun := flag.Bool("dry-run", false, "print plan, don't execute")
	flag.Parse()

	all := []stageDef{
		{1, "memfd_create + exec from memory",
			[]string{"ebpf.shm_exec", "shm.exec"}, stageMemfdExec},
		{2, "deleted-binary-running",
			[]string{"procmem.deleted_binary_running"}, stageDeletedBinaryRunning},
		{3, "honey-decoy file read",
			[]string{"credbroker.honey_touched"}, stageHoneyRead},
		{4, "sealed-credential open from no-contract",
			[]string{"credbroker.unauthentic_open"}, stageSealedRead},
		{5, "RWX anonymous mmap",
			[]string{"mem_mprotect_rwx", "rwx_mprotect"}, stageRWXMmap},
		{6, "parent-mismatch shell spawn (httpd→bash→curl)",
			[]string{"parent_mismatch", "shell_with_socket_fd"}, stageParentMismatch},
		{7, "cron persistence drop",
			[]string{"cron_new_unit", "user_crontab_modified"}, stageCronDrop},
		{8, "outbound to TEST-NET-1 (exfil-shape, RFC5737)",
			[]string{"egress.unknown_destination", "intel.bad_ip"}, stageExfilShape},
	}

	want := map[int]bool{}
	if *flagStages == "all" {
		for _, s := range all {
			want[s.num] = true
		}
	} else {
		for _, tok := range strings.Split(*flagStages, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(tok))
			if err == nil {
				want[n] = true
			}
		}
	}

	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println("  xhelix C2 simulator — Tier-1 deterministic behaviour matrix")
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Printf("  host=%s pid=%d uid=%d\n", hostname(), os.Getpid(), os.Geteuid())
	fmt.Printf("  start_time=%s\n\n", time.Now().UTC().Format(time.RFC3339))

	executed := 0
	failed := 0
	for _, s := range all {
		if !want[s.num] {
			continue
		}
		fmt.Printf("STAGE %d: %s\n", s.num, s.name)
		fmt.Printf("  expected_rules: %s\n", strings.Join(s.expected, ", "))
		if *flagDryRun {
			fmt.Printf("  (dry-run; skipping)\n\n")
			continue
		}
		if err := s.fn(); err != nil {
			fmt.Printf("  FAILED: %v\n\n", err)
			failed++
			continue
		}
		fmt.Printf("  done.\n\n")
		executed++
		// Small gap so xhelix can attribute alerts to discrete stages.
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Printf("  executed=%d failed=%d skipped=%d\n", executed, failed, len(all)-executed-failed)
	fmt.Println("  Verify with:")
	fmt.Println("    journalctl -u xhelix --since '5min ago' | grep -E 'rule_id|critical'")
	fmt.Println("    xhelixctl egress observe")
	fmt.Println("    xhelixctl alerts --since 5m       (if alerts command exists)")
	fmt.Println("══════════════════════════════════════════════════════════════")
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

// ─── Stage 1: memfd_create + exec from memory ──────────────────────

func stageMemfdExec() error {
	// Build a trivial /bin/true equivalent at runtime: actually we'll
	// just copy /bin/true into a memfd and exec it. The detection
	// signal is "process executed from a non-file-backed fd."
	src, err := os.Open("/bin/true")
	if err != nil {
		return err
	}
	defer src.Close()
	fd, err := unix.MemfdCreate("c2sim-payload", unix.MFD_CLOEXEC)
	if err != nil {
		return fmt.Errorf("memfd_create: %w", err)
	}
	defer unix.Close(fd)
	memFile := os.NewFile(uintptr(fd), "memfd")
	if _, err := io.Copy(memFile, src); err != nil {
		return err
	}
	// Exec via /proc/self/fd/N (a memfd is exec-able through that path).
	cmd := exec.Command(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err := cmd.Run(); err != nil {
		// /bin/true returns 0; any error here is structural.
		return err
	}
	fmt.Println("  ran payload from memfd successfully (mimics in-memory loader)")
	return nil
}

// ─── Stage 2: deleted-binary-running ───────────────────────────────

func stageDeletedBinaryRunning() error {
	// Copy a real binary to /tmp, fork+exec it, then unlink while the
	// child is still running. xhelix sensors/procmem detects via
	// /proc/<pid>/exe link containing " (deleted)".
	tmp, err := os.CreateTemp("", "c2sim-deleted-*")
	if err != nil {
		return err
	}
	path := tmp.Name()
	tmp.Close()
	defer os.Remove(path) // safety
	// Copy /bin/sleep so we have a process that lives long enough.
	if err := copyFile("/bin/sleep", path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o755); err != nil {
		return err
	}
	cmd := exec.Command(path, "2")
	if err := cmd.Start(); err != nil {
		return err
	}
	// Give it a moment to be running, then delete the on-disk copy.
	time.Sleep(200 * time.Millisecond)
	_ = os.Remove(path)
	fmt.Printf("  /bin/sleep copied to %s, exec'd, then unlinked while running pid=%d\n",
		path, cmd.Process.Pid)
	_ = cmd.Wait()
	return nil
}

// ─── Stage 3: honey-decoy file read ────────────────────────────────

func stageHoneyRead() error {
	// xhelix's credbroker decoys live at /etc/xhelix/sealed/*.honey
	// by default. We just open and read.
	matches, err := filepath.Glob("/etc/xhelix/sealed/*.honey")
	if err != nil || len(matches) == 0 {
		fmt.Println("  no .honey files found — skipping (drop one first via 'xhelixctl credbroker decoy drop')")
		return nil
	}
	for _, p := range matches {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		fmt.Printf("  read %d bytes from %s (honey marker should be in content)\n", len(data), p)
		break
	}
	return nil
}

// ─── Stage 4: sealed-credential open from no-contract caller ───────

func stageSealedRead() error {
	matches, err := filepath.Glob("/etc/xhelix/sealed/*.sealed")
	if err != nil || len(matches) == 0 {
		fmt.Println("  no .sealed files found — skipping (run xhelixctl credbroker seal first)")
		return nil
	}
	for _, p := range matches {
		// We're 'c2-sim', NOT in any Layer-2 contract. broker.Decide
		// must DENY → fangate replies EACCES.
		_, err := os.ReadFile(p)
		if err != nil {
			fmt.Printf("  open(%s) → %v   (DENIED as expected)\n", p, err)
		} else {
			fmt.Printf("  open(%s) succeeded — UNEXPECTED, gate may be disabled\n", p)
		}
		break
	}
	return nil
}

// ─── Stage 5: RWX anonymous mmap ───────────────────────────────────

func stageRWXMmap() error {
	// Anonymous PROT_READ|PROT_WRITE|PROT_EXEC mmap — the shape of
	// shellcode landing in memory before jumping into it.
	const sz = 4096
	mem, err := unix.Mmap(-1, 0, sz,
		unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC,
		unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return err
	}
	defer unix.Munmap(mem)
	// Write a tiny no-op-then-ret on x86_64 so a real exec would
	// have succeeded. We don't actually jump there — that'd crash us
	// with no useful additional signal.
	// 0x90 = NOP, 0xc3 = RET
	mem[0] = 0x90
	mem[1] = 0xc3
	fmt.Println("  RWX page mapped (4096 bytes) — shape of shellcode loader")
	return nil
}

// ─── Stage 6: parent-mismatch (httpd→bash→curl) ────────────────────

func stageParentMismatch() error {
	// We can't really fake being httpd, but we can chain bash → curl
	// with the comm-name signal that triggers parent_mismatch when
	// the chain root looks unusual. This is the closest userland
	// can get without forking + execve-with-comm-rename privileges.
	cmd := exec.Command("bash", "-c", "exec sh -c 'echo c2sim-parent-mismatch'")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	fmt.Printf("  bash→sh chain: %s\n", strings.TrimSpace(string(out)))
	return nil
}

// ─── Stage 7: cron persistence drop ────────────────────────────────

func stageCronDrop() error {
	cronFile := fmt.Sprintf("/etc/cron.d/xhelix-c2sim-%d", time.Now().Unix())
	body := "# C2 simulator persistence drop\n* * * * * root /bin/true\n"
	if err := os.WriteFile(cronFile, []byte(body), 0o644); err != nil {
		fmt.Printf("  cron drop failed (probably need root): %v\n", err)
		return nil
	}
	fmt.Printf("  cron file dropped: %s\n", cronFile)
	// Remove immediately so we don't leave persistence.
	time.Sleep(200 * time.Millisecond)
	_ = os.Remove(cronFile)
	fmt.Printf("  cleaned up: %s\n", cronFile)
	return nil
}

// ─── Stage 8: outbound to TEST-NET-1 ───────────────────────────────

func stageExfilShape() error {
	// RFC5737 TEST-NET-1: 192.0.2.0/24, never routes. We do three
	// short connects spaced ~200ms apart so the egress observer sees
	// the unique-unknown pattern + classifies them all as Unknown.
	targets := []string{
		"192.0.2.42:443",
		"198.51.100.99:443",
		"203.0.113.5:443",
	}
	for _, t := range targets {
		conn, err := net.DialTimeout("tcp", t, 1*time.Second)
		if err != nil {
			fmt.Printf("  connect %s → %v (expected: refused/timeout)\n", t, err)
		} else {
			fmt.Printf("  connect %s → unexpectedly succeeded\n", t)
			conn.Close()
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil
}

// ─── helpers ───────────────────────────────────────────────────────

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// Silence linter for unused syscall import on some build paths.
var _ = syscall.Stat
