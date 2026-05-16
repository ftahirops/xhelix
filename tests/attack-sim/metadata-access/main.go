// sim-metadata-access simulates a cloud metadata service request.
// xhelix rule `metadata_svc_unexpected` detects outbound connections
// to 169.254.169.254 from non-allowlisted processes.
//
// Safe: performs an HTTP GET to the metadata endpoint. On non-cloud
// hosts this will simply fail (no route). The connection attempt is
// what xhelix observes.
//
// Expected xhelix alert:
//
//	rule: metadata_svc_unexpected
//	severity: high
//	tags: credential_access, cloud
package main

import (
	"fmt"
	"net/http"
	"time"
)

func main() {
	fmt.Println("[SIM] metadata_svc_unexpected")
	fmt.Println("      Connecting to http://169.254.169.254/")
	fmt.Println("      This triggers xhelix rule: metadata_svc_unexpected")

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://169.254.169.254/")
	if err != nil {
		fmt.Printf("      (expected failure on non-cloud host): %v\n", err)
	} else {
		resp.Body.Close()
		fmt.Printf("      response status: %s\n", resp.Status)
	}
	fmt.Println("[SIM] done")
}
