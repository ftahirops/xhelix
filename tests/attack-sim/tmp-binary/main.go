// sim-tmp-binary simulates running a binary from /tmp — a common
// dropper pattern detected by xhelix rule `binary_runs_from_tmp`.
//
// Safe: writes a tiny harmless Go binary to /tmp, executes it, then
// cleans up.
//
// Expected xhelix alert:
//
//	rule: binary_runs_from_tmp
//	severity: warn
//	tags: post_exploitation, dropper
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	tmpBin := filepath.Join(os.TempDir(), "xhelix-sim-dropper")

	fmt.Println("[SIM] binary_runs_from_tmp")
	fmt.Printf("      Compiling harmless binary to %s\n", tmpBin)
	fmt.Println("      This triggers xhelix rule: binary_runs_from_tmp")

	src := `package main
func main() { println("I am a simulated dropper") }
`
	tmpSrc := tmpBin + ".go"
	if err := os.WriteFile(tmpSrc, []byte(src), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write src: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(tmpSrc)

	cmd := exec.Command("go", "build", "-o", tmpBin, tmpSrc)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(tmpBin)

	run := exec.Command(tmpBin)
	run.Stdout = os.Stdout
	run.Stderr = os.Stderr
	if err := run.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "run failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SIM] done")
}
