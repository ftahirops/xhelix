package recorder

import (
	"testing"

	"github.com/xhelix/xhelix/pkg/model"
)

func ev(sensor, comm, image string, tags map[string]string) model.Event {
	return model.Event{Sensor: sensor, Comm: comm, Image: image, Tags: tags}
}

func TestEdgeFromEvent_Exec(t *testing.T) {
	e, ok := EdgeFromEvent(ev("ebpf.spawn", "curl", "/usr/bin/curl", nil))
	if !ok || e.Kind != EdgeExec {
		t.Fatalf("want exec edge, got %+v ok=%v", e, ok)
	}
	if e.Key != "curl" {
		t.Errorf("exec Key = %q, want \"curl\"", e.Key)
	}
}

func TestEdgeFromEvent_Egress_PrefersSNIThenIP(t *testing.T) {
	e, ok := EdgeFromEvent(ev("net_connect", "", "", map[string]string{
		"sni": "api.stripe.com", "dst_ip": "1.2.3.4", "dst_port": "443",
	}))
	if !ok || e.Kind != EdgeEgress {
		t.Fatalf("want egress edge, got %+v ok=%v", e, ok)
	}
	if e.Key != "api.stripe.com:443" {
		t.Errorf("egress Key = %q, want host:port", e.Key)
	}
	// Falls back to dst_ip when no SNI.
	e2, _ := EdgeFromEvent(ev("net_connect", "", "", map[string]string{"dst_ip": "1.2.3.4", "dst_port": "443"}))
	if e2.Key != "1.2.3.4:443" {
		t.Errorf("egress fallback Key = %q, want ip:port", e2.Key)
	}
}

func TestEdgeFromEvent_Write_KeyIsDirRawIsFullPath(t *testing.T) {
	// Key coarsens to the parent dir so "same workflow, different leaf file"
	// groups into ONE shape; Raw keeps the full path for the generalizer.
	e, ok := EdgeFromEvent(ev("fim.drift", "", "", map[string]string{"path": "/var/www/site-a/wp-content/uploads/2026/a.jpg"}))
	if !ok || e.Kind != EdgeWrite {
		t.Fatalf("want write edge, got %+v ok=%v", e, ok)
	}
	if e.Key != "/var/www/site-a/wp-content/uploads/2026" {
		t.Errorf("write Key = %q, want parent dir", e.Key)
	}
	if e.Raw != "/var/www/site-a/wp-content/uploads/2026/a.jpg" {
		t.Errorf("write Raw = %q, want full path", e.Raw)
	}
}

func TestEdgeFromEvent_NotAnEdge(t *testing.T) {
	if _, ok := EdgeFromEvent(ev("heartbeat", "", "", nil)); ok {
		t.Error("heartbeat must not be a recordable edge")
	}
	if _, ok := EdgeFromEvent(ev("ebpf.net", "", "", map[string]string{})); ok {
		t.Error("net event with no dst must not be an edge")
	}
}
