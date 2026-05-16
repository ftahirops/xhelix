// sim-pam-module-drop simulates dropping a new .so file into the
// PAM module directory. xhelix rule `pam_module_drop` detects this.
//
// Safe: creates a dummy .so file in /tmp (not the real PAM dir),
// demonstrating the file pattern. To trigger the real rule you would
// need root and write to /lib/security/.
//
// Expected xhelix alert (if FIM watches PAM dirs):
//
//	rule: pam_module_drop
//	severity: critical
//	tags: persistence, credential_access
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	// Use /tmp for safety; real attackers target /lib/security/
	pamDir := "/tmp/xhelix-sim-pam"
	modFile := filepath.Join(pamDir, "xhelix_test.so")

	fmt.Println("[SIM] pam_module_drop")
	fmt.Printf("      Creating dummy PAM module at %s\n", modFile)
	fmt.Println("      NOTE: real rule fires on /lib/security/*.so")
	fmt.Println("      This demonstrates the file creation pattern")

	_ = os.MkdirAll(pamDir, 0o755)
	if err := os.WriteFile(modFile, []byte("SIMULATED_PAM_MODULE"), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write failed: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(pamDir)

	fmt.Println("      Dummy .so created and removed")
	fmt.Println("[SIM] done")
}
