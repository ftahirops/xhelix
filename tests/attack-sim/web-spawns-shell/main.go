// sim-web-spawns-shell simulates a web server worker spawning an
// interactive shell — the classic post-exploitation pattern that
// xhelix rule `web_server_spawns_shell` detects.
//
// Safe: this renames the current process to "nginx" via argv[0]
// and then execs /bin/sh. It does NOT exploit anything; it merely
// reproduces the behavioral signature.
//
// Expected xhelix alert:
//
//	rule: web_server_spawns_shell
//	severity: high
//	tags: post_exploitation, web
package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	fmt.Println("[SIM] web_server_spawns_shell")
	fmt.Println("      Renaming process to 'nginx' then execing /bin/sh")
	fmt.Println("      This triggers xhelix rule: web_server_spawns_shell")

	// Re-exec with argv[0] = "nginx" to fool comm-based detection
	cmd := exec.Command("/bin/sh", "-c", "echo 'shell spawned by fake nginx'; exit 0")
	cmd.Args[0] = "nginx" // comm will appear as "nginx" in parent
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "run failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SIM] done")
}
