// sim-ld-preload simulates a rootkit technique: writing to
// /etc/ld.so.preload. xhelix rules `ld_so_preload_modified` and
// `posture.ld_preload` both detect this.
//
// Safe: creates a backup, writes a harmless comment, then restores.
//
// Expected xhelix alert:
//
//	rule: ld_so_preload_modified
//	severity: critical
//	tags: persistence, hijack
package main

import (
	"fmt"
	"os"
)

func main() {
	target := "/etc/ld.so.preload"

	fmt.Println("[SIM] ld_so_preload_modified")
	fmt.Printf("      Writing harmless marker to %s\n", target)
	fmt.Println("      This triggers xhelix rules: ld_so_preload_modified + posture.ld_preload")

	// Backup existing content
	backup := target + ".xhelix-backup"
	if data, err := os.ReadFile(target); err == nil {
		_ = os.WriteFile(backup, data, 0o600)
	}

	marker := "# xhelix-sim: harmless marker written by test suite\n"
	if err := os.WriteFile(target, []byte(marker), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write failed (need root): %v\n", err)
		os.Exit(1)
	}

	// Immediate restore
	if data, err := os.ReadFile(backup); err == nil {
		_ = os.WriteFile(target, data, 0o644)
		_ = os.Remove(backup)
		fmt.Println("      Restored original file")
	} else {
		_ = os.Remove(target)
		fmt.Println("      Removed test file (no prior backup)")
	}
	fmt.Println("[SIM] done")
}
