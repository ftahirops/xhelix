package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/egressledger"
	"github.com/xhelix/xhelix/pkg/model"
)

// TestEgressStampsServiceRoleAndParentComm is the EO3-T4 contract: at the
// egress observe site the binary is classified into a service_role and the
// originating process's parent_comm is stamped onto the egressledger.Event
// before Observe is called.
func TestEgressStampsServiceRoleAndParentComm(t *testing.T) {
	led, err := egressledger.New(egressledger.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}

	p := &Pipeline{EgressLedger: led}

	ev := model.NewEvent("ebpf.net", model.SeverityInfo)
	ev.PID = 1234
	ev.Image = "/usr/sbin/mysqld"
	ev.Comm = "mysqld"
	ev.Tags["kind"] = "net_connect"
	ev.Tags["dst_ip"] = "1.2.3.4"
	ev.Tags["dst_port"] = "443"
	// Provide parent_comm directly to isolate the stamping from proctree.
	ev.Tags["parent_comm"] = "systemd"
	p.Handle(context.Background(), ev)

	rows := led.QueryRecent(time.Now().Add(-time.Hour), nil, "", 10)
	if len(rows) == 0 {
		t.Fatalf("no recent egress rows recorded")
	}
	got := rows[0]
	if got.ServiceRole != "database" {
		t.Fatalf("ServiceRole = %q, want database", got.ServiceRole)
	}
	if got.ParentComm != "systemd" {
		t.Fatalf("ParentComm = %q, want systemd", got.ParentComm)
	}
}
