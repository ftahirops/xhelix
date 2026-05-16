// sim-suid-binary simulates creating a new SUID binary outside the
// package manager. xhelix rules `suid_binary_created` and posture
// `suid_drift` detect this.
//
// Safe: writes a harmless binary to /tmp, chmod +s, then removes it.
//
// Expected xhelix alert:
//
//	rule: suid_binary_created  (FIM rule if watch_paths covers /tmp)
//	posture: suid_drift
//	severity: warn / critical
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	tmpBin := filepath.Join(os.TempDir(), "xhelix-sim-suid")

	fmt.Println("[SIM] suid_binary_created / suid_drift")
	fmt.Printf("      Creating SUID binary at %s\n", tmpBin)
	fmt.Println("      This triggers xhelix FIM + posture rules")

	src := `package main
func main() { println("I am a simulated SUID binary") }
`
	tmpSrc := tmpBin + ".go"
	_ = os.WriteFile(tmpSrc, []byte(src), 0o644)
	defer os.Remove(tmpSrc)

	cmd := exec.Command("go", "build", "-o", tmpBin, tmpSrc)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(tmpBin)

	if err := os.Chmod(tmpBin, 0o4755); err != nil {
		fmt.Fprintf(os.Stderr, "chmod failed: %v\n", err)
		os.Exit(1)
	}

	// Verify
	info, _ := os.Stat(tmpBin)
	if info != nil && info.Mode()&os.ModeSetuid != 0 {
		fmt.Println("      SUID bit set successfully")
	}
	fmt.Println("[SIM] done (file removed)")
}
