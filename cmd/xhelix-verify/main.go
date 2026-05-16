// Command xhelix-verify validates the tamper-evident hash chain
// produced by xhelix.
//
// Designed to run on a trusted host (not the same one the chain
// came from). Investigators copy the chain directory and the host's
// public key here, then run:
//
//	xhelix-verify --chain /path/to/chain --pub /path/to/pubkey
//
// Exit code is 0 on success, non-zero on any verification failure.
//
// This binary deliberately depends only on pkg/chain — the smallest
// possible verifier surface.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/xhelix/xhelix/pkg/chain"
)

func main() {
	var (
		chainDir = flag.String("chain", "", "directory containing batch files")
		pubPath  = flag.String("pub", "", "path to host's Ed25519 public key (hex or raw 32 bytes)")
	)
	flag.Parse()

	if *chainDir == "" || *pubPath == "" {
		fmt.Fprintln(os.Stderr, "usage: xhelix-verify --chain DIR --pub KEYFILE")
		os.Exit(2)
	}

	pub, err := loadPublicKey(*pubPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load pubkey:", err)
		os.Exit(2)
	}

	n, err := chain.Verify(*chainDir, pub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "VERIFY FAILED after %d batches: %v\n", n, err)
		os.Exit(1)
	}
	fmt.Printf("OK: %d batches verified\n", n)
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	body = []byte(strings.TrimSpace(string(body)))
	// Hex form?
	if len(body) == ed25519.PublicKeySize*2 {
		raw, err := hex.DecodeString(string(body))
		if err == nil {
			return ed25519.PublicKey(raw), nil
		}
	}
	// Raw form?
	if len(body) == ed25519.PublicKeySize {
		return ed25519.PublicKey(body), nil
	}
	return nil, fmt.Errorf("expected %d hex chars or %d raw bytes, got %d bytes",
		ed25519.PublicKeySize*2, ed25519.PublicKeySize, len(body))
}
