// sim-dga-dns simulates a DNS query to a DGA-looking domain.
// xhelix NetIDS DGA heuristic flags high-entropy random-looking
// query names.
//
// Safe: uses net.LookupHost on a randomly-generated domain. No actual
// C2 communication occurs.
//
// Expected xhelix alert (when NetIDS processes DNS events):
//
//	rule: netids.dga
//	severity: high
//	reason: DGA score > 0.7
package main

import (
	"fmt"
	"math/rand"
	"net"
	"time"
)

func main() {
	fmt.Println("[SIM] netids.dga")
	fmt.Println("      Querying random-looking domain")
	fmt.Println("      This triggers xhelix DGA heuristic")

	// Generate a DGA-looking domain
	domain := randomString(20) + ".com"
	fmt.Printf("      Querying: %s\n", domain)

	_, err := net.LookupHost(domain)
	if err != nil {
		fmt.Printf("      (expected NXDOMAIN): %v\n", err)
	}
	fmt.Println("[SIM] done")
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
