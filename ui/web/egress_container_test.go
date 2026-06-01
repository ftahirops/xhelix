package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xhelix/xhelix/pkg/egressledger"
)

// TestHistoricalPIDContainerJSON asserts that the container-origin fields
// from a recent ProcEvent survive the ProcEvent→HistoricalPID mapping and
// appear in the JSON the egress drilldowns serve.
func TestHistoricalPIDContainerJSON(t *testing.T) {
	e := egressledger.ProcEvent{
		PID:            1234,
		Comm:           "curl",
		Binary:         "/usr/bin/curl",
		ContainerClass: "container",
		ContainerID:    "abcdef0123456789",
		Unit:           "docker-abcdef.scope",
	}

	h := HistoricalPID{
		PID: e.PID, Comm: e.Comm, Binary: e.Binary,
		ContainerID:    e.ContainerID,
		ContainerClass: e.ContainerClass,
		Unit:           e.Unit,
		Container:      containerCell(e.ContainerClass, e.ContainerID),
	}

	b, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(b)

	if !strings.Contains(js, `"container_class":"container"`) {
		t.Errorf("missing container_class in JSON: %s", js)
	}
	// Short id (first 12 chars) must be the display token.
	if !strings.Contains(js, `"container":"abcdef012345"`) {
		t.Errorf("missing short container id in JSON: %s", js)
	}
	if !strings.Contains(js, `"container_id":"abcdef0123456789"`) {
		t.Errorf("missing full container_id in JSON: %s", js)
	}
}

// TestHistoricalPIDServiceRoleJSON asserts that ServiceRole + ParentComm
// from a recent ProcEvent survive the ProcEvent→HistoricalPID mapping and
// appear in the JSON the egress drilldowns serve.
func TestHistoricalPIDServiceRoleJSON(t *testing.T) {
	e := egressledger.ProcEvent{
		PID:         4321,
		Comm:        "mysqld",
		Binary:      "/usr/sbin/mysqld",
		ServiceRole: "database",
		ParentComm:  "systemd",
	}

	h := HistoricalPID{
		PID: e.PID, Comm: e.Comm, Binary: e.Binary,
		ServiceRole: e.ServiceRole,
		ParentComm:  e.ParentComm,
	}

	b, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(b)

	if !strings.Contains(js, `"service_role":"database"`) {
		t.Errorf("missing service_role in JSON: %s", js)
	}
	if !strings.Contains(js, `"parent_comm":"systemd"`) {
		t.Errorf("missing parent_comm in JSON: %s", js)
	}
}
