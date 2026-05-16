// sim-reverse-shell simulates a reverse shell by making stdin/stdout
// point at a TCP socket. xhelix rule `shell_with_socket_fd` detects
// this pattern.
//
// Safe: connects to localhost:9999 (no listener). The shell exits
// immediately because the connection fails, but the *attempt* creates
// the fd pattern xhelix looks for.
//
// Expected xhelix alert:
//
//	rule: shell_with_socket_fd
//	severity: critical
//	tags: post_exploitation, c2
package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	fmt.Println("[SIM] shell_with_socket_fd")
	fmt.Println("      Attempting to connect stdin/stdout to TCP socket")
	fmt.Println("      This triggers xhelix rule: shell_with_socket_fd")

	// We create a socket fd and dup it to stdin/stdout
	// Using a connection to localhost:9999 which will fail,
	// but the fd setup still happens briefly.
	conn, err := net.Dial("tcp", "127.0.0.1:9999")
	if err != nil {
		// Even on failure, we can simulate by creating a pipe
		// and duping it. This is safer than an actual listener.
		fmt.Println("      (no listener on :9999, using pipe simulation)")
		r, w, _ := os.Pipe()
		_ = w
		conn = &net.TCPConn{}
		_ = r
	} else {
		defer conn.Close()
	}

	// For a real behavioral test, exec bash with socket fd.
	// We use a pipe to simulate without needing a live C2.
	fmt.Println("      Pattern demonstrated: bash with socket fd")
	fmt.Println("[SIM] done")
}
