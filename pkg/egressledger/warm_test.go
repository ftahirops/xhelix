package egressledger

import (
	"testing"
	"time"
)

// TestWarmRoundTripServiceRoleParentComm is a regression guard: the warm
// store gob-encodes the whole FlowRecord, so ServiceRole/ParentComm survive
// with NO code change. This test pins that behavior so a future field-list
// gob change can't silently drop them.
func TestWarmRoundTripServiceRoleParentComm(t *testing.T) {
	rec := FlowRecord{
		Key: FlowKey{
			Binary:   "/usr/sbin/mysqld",
			DestPort: 3306,
			Protocol: "tcp",
		},
		Metrics: FlowMetrics{
			FirstSeen:   time.Unix(0, 1),
			LastSeen:    time.Unix(0, 2),
			Connects:    1,
			ServiceRole: "database",
			ParentComm:  "sshd",
		},
		Bucket: time.Unix(0, 1),
	}
	b, err := encodeValue(rec)
	if err != nil {
		t.Fatalf("encodeValue: %v", err)
	}
	got, err := decodeValue(b)
	if err != nil {
		t.Fatalf("decodeValue: %v", err)
	}
	if got.Metrics.ServiceRole != "database" {
		t.Errorf("ServiceRole: got %q want %q", got.Metrics.ServiceRole, "database")
	}
	if got.Metrics.ParentComm != "sshd" {
		t.Errorf("ParentComm: got %q want %q", got.Metrics.ParentComm, "sshd")
	}
}

func TestMergeRecord_CarriesServiceRoleParentComm(t *testing.T) {
	a := FlowRecord{Metrics: FlowMetrics{ServiceRole: "web", ParentComm: "init"}}
	b := FlowRecord{Metrics: FlowMetrics{ServiceRole: "database", ParentComm: "sshd"}}
	got := mergeRecord(a, b)
	if got.Metrics.ServiceRole != "database" || got.Metrics.ParentComm != "sshd" {
		t.Fatalf("merge dropped descriptive fields: %+v", got.Metrics)
	}
	// empty incoming must NOT erase an existing value
	got2 := mergeRecord(b, FlowRecord{Metrics: FlowMetrics{}})
	if got2.Metrics.ServiceRole != "database" || got2.Metrics.ParentComm != "sshd" {
		t.Fatalf("empty incoming erased existing: %+v", got2.Metrics)
	}
}
