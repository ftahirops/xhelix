package top

import (
	"fmt"
	"io"
	"os"
)

// readFileLimited reads up to maxBytes from path. Prevents the TUI
// from blowing up if the rollup file is huge.
func readFileLimited(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxBytes))
}
