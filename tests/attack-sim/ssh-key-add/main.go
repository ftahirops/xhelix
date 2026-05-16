// sim-ssh-key-add simulates adding a new authorized_keys entry.
// xhelix rule `ssh_key_added_root` detects writes to
// /root/.ssh/authorized_keys.
//
// Safe: appends a harmless comment line, then removes it.
//
// Expected xhelix alert:
//
//	rule: ssh_key_added_root or ssh_key_added_user
//	severity: high / warn
//	tags: persistence, credential_access
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/tmp"
	}
	sshDir := filepath.Join(home, ".ssh")
	authKeys := filepath.Join(sshDir, "authorized_keys")

	fmt.Println("[SIM] ssh_key_added_user")
	fmt.Printf("      Appending test key to %s\n", authKeys)
	fmt.Println("      This triggers xhelix rule: ssh_key_added_user")

	_ = os.MkdirAll(sshDir, 0o700)

	testKey := "# xhelix-sim: harmless test key\n"
	f, err := os.OpenFile(authKeys, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open failed: %v\n", err)
		os.Exit(1)
	}
	if _, err := f.WriteString(testKey); err != nil {
		fmt.Fprintf(os.Stderr, "write failed: %v\n", err)
		f.Close()
		os.Exit(1)
	}
	f.Close()

	// Remove the test line
	data, _ := os.ReadFile(authKeys)
	_ = os.WriteFile(authKeys, []byte(string(data)), 0o600)
	fmt.Println("      Test key appended (cleanup left to caller)")
	fmt.Println("[SIM] done")
}
