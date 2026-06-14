package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/cgroupclass"
	"github.com/xhelix/xhelix/pkg/egressledger"
	"github.com/xhelix/xhelix/pkg/model"
)

// TestEgressStampsContainerOrigin is the Task 3 contract: at the egress
// observe site the originating PID is classified and its container
// origin (id / class / unit) is stamped onto the egressledger.Event
// before Observe is called.
func TestEgressStampsContainerOrigin(t *testing.T) {
	led, err := egressledger.New(egressledger.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}

	p := &Pipeline{
		EgressLedger: led,
		CGroupClassifier: cgroupclass.NewWithReader(8, func(string) ([]byte, error) {
			return []byte("0::/system.slice/docker-9f8e7d6c5b4a3210fedcba9876543210fedcba9876543210fedcba9876543210.scope\n"), nil
		}),
	}

	ev := model.NewEvent("ebpf.net", model.SeverityInfo)
	ev.PID = 1234
	ev.Tags["kind"] = "net_connect"
	ev.Tags["dst_ip"] = "1.2.3.4"
	ev.Tags["dst_port"] = "443"
	p.Handle(context.Background(), ev)

	rows := led.QueryRecent(time.Now().Add(-time.Hour), nil, "", 10)
	if len(rows) == 0 {
		t.Fatalf("no recent egress rows recorded")
	}
	got := rows[0]
	if got.ContainerClass != "container" {
		t.Fatalf("ContainerClass = %q, want container", got.ContainerClass)
	}
	if got.ContainerID == "" {
		t.Fatalf("ContainerID empty, want non-empty")
	}
}
