package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/xhelix/xhelix/pkg/xhubfleet"
)

// trustFileName is the per-host trust snapshot kept under the data dir.
const trustFileName = "trust.json"

// saveTrust writes the ranker's host records to <dir>/trust.json
// atomically (tmp file + rename). The hub's upload rate is low, so
// saving on each ingest is acceptable.
func saveTrust(dir string, r *xhubfleet.TrustRanker) error {
	records := r.All()
	body, err := json.Marshal(records)
	if err != nil {
		return err
	}
	dst := filepath.Join(dir, trustFileName)
	tmp, err := os.CreateTemp(dir, trustFileName+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// loadTrust reads <dir>/trust.json into the ranker. A missing file is
// not an error (first run).
func loadTrust(dir string, r *xhubfleet.TrustRanker) error {
	body, err := os.ReadFile(filepath.Join(dir, trustFileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	var records []xhubfleet.HostRecord
	if err := json.Unmarshal(body, &records); err != nil {
		return err
	}
	r.Restore(records)
	return nil
}

// readFileOK is a thin os.ReadFile wrapper used by tests to assert a
// file exists and is readable.
func readFileOK(path string) ([]byte, error) {
	return os.ReadFile(path)
}
