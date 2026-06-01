package egressledger

import (
	"path/filepath"
	"testing"
	"time"
)

// TestColdRoundTripServiceRoleParentComm proves that ServiceRole and
// ParentComm survive a full cold-store write/read cycle (parquet on disk).
func TestColdRoundTripServiceRoleParentComm(t *testing.T) {
	dir := t.TempDir()
	c, err := newColdStore(dir)
	if err != nil {
		t.Fatalf("newColdStore: %v", err)
	}
	bucket := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	rec := FlowRecord{
		Key: FlowKey{
			Binary:    "/usr/sbin/mysqld",
			ExeSHA:    "abc123",
			UID:       1000,
			CGroupID:  42,
			DestCIDR:  "10.0.0.0/16",
			DestPort:  3306,
			Protocol:  "tcp",
			DestClass: "internal",
		},
		Metrics: FlowMetrics{
			FirstSeen:   bucket,
			LastSeen:    bucket.Add(time.Minute),
			Connects:    3,
			BytesOut:    100,
			BytesIn:     200,
			ServiceRole: "database",
			ParentComm:  "sshd",
		},
		Bucket: bucket,
	}
	if err := c.appendRecords([]FlowRecord{rec}); err != nil {
		t.Fatalf("appendRecords: %v", err)
	}
	var got []FlowRecord
	if err := c.scan(bucket.Add(-time.Hour), bucket.Add(time.Hour), func(r FlowRecord) bool {
		got = append(got, r)
		return true
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 record, got %d", len(got))
	}
	if got[0].Metrics.ServiceRole != "database" {
		t.Errorf("ServiceRole: got %q want %q", got[0].Metrics.ServiceRole, "database")
	}
	if got[0].Metrics.ParentComm != "sshd" {
		t.Errorf("ParentComm: got %q want %q", got[0].Metrics.ParentComm, "sshd")
	}
}

// TestColdRowConverterRoundTrip is the lowest-level guard: recordToRow ->
// rowToRecord preserves the two new descriptive columns.
func TestColdRowConverterRoundTrip(t *testing.T) {
	rec := FlowRecord{
		Metrics: FlowMetrics{
			ServiceRole: "cache",
			ParentComm:  "systemd",
		},
		Bucket: time.Unix(0, 1),
	}
	got := rowToRecord(recordToRow(rec))
	if got.Metrics.ServiceRole != "cache" {
		t.Errorf("ServiceRole: got %q want %q", got.Metrics.ServiceRole, "cache")
	}
	if got.Metrics.ParentComm != "systemd" {
		t.Errorf("ParentComm: got %q want %q", got.Metrics.ParentComm, "systemd")
	}
}

// TestColdOldFileTolerance documents that a parquetRow with the new columns
// left empty (as a pre-existing parquet file written before these columns
// existed would read back) round-trips to empty strings without error.
// parquet-go zero-fills columns absent from older files.
func TestColdOldFileTolerance(t *testing.T) {
	// Simulate an old row: everything except the new columns populated.
	old := parquetRow{
		BucketUnixNano: time.Unix(0, 5).UnixNano(),
		Binary:         "/bin/curl",
		DestPort:       443,
		Protocol:       "tcp",
		// ServiceRole and ParentComm intentionally left zero ("").
	}
	rec := rowToRecord(old)
	if rec.Metrics.ServiceRole != "" {
		t.Errorf("old-file ServiceRole: got %q want empty", rec.Metrics.ServiceRole)
	}
	if rec.Metrics.ParentComm != "" {
		t.Errorf("old-file ParentComm: got %q want empty", rec.Metrics.ParentComm)
	}

	// And it survives an actual disk write/read too.
	dir := t.TempDir()
	path := filepath.Join(dir, "events.parquet")
	if err := writeParquet(path, []parquetRow{old}); err != nil {
		t.Fatalf("writeParquet: %v", err)
	}
	rows, err := readParquet(path)
	if err != nil {
		t.Fatalf("readParquet: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].ServiceRole != "" || rows[0].ParentComm != "" {
		t.Errorf("disk round-trip of empty columns: got role=%q comm=%q want empty",
			rows[0].ServiceRole, rows[0].ParentComm)
	}
}
