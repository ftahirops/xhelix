// sim-python-c2 simulates a Python interpreter making an outbound
// connection to a public IP. xhelix rule `suspicious_interpreter_network`
// detects this pattern.
//
// Safe: uses Python's urllib to fetch example.com. No actual C2.
//
// Expected xhelix alert:
//
//	rule: suspicious_interpreter_network
//	severity: high
//	tags: c2, scripting
package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	fmt.Println("[SIM] suspicious_interpreter_network")
	fmt.Println("      Launching python3 to fetch public URL")
	fmt.Println("      This triggers xhelix rule: suspicious_interpreter_network")

	script := `import urllib.request
try:
    urllib.request.urlopen('http://example.com/', timeout=3)
except Exception as e:
    print('fetch result:', e)
`
	cmd := exec.Command("python3", "-c", script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "python run failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[SIM] done")
}
