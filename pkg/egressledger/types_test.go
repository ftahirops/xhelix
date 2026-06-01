package egressledger

import "testing"

func TestEvent_ContainerFields(t *testing.T) {
	e := Event{ContainerID: "9f8e7d6c", ContainerClass: "container", Unit: "docker-9f8e7d6c.scope"}
	if e.ContainerID != "9f8e7d6c" || e.ContainerClass != "container" || e.Unit != "docker-9f8e7d6c.scope" {
		t.Fatalf("container fields not retained: %+v", e)
	}
}

func TestEvent_ServiceRoleParentComm(t *testing.T) {
	e := Event{ServiceRole: "database", ParentComm: "systemd"}
	if e.ServiceRole != "database" || e.ParentComm != "systemd" {
		t.Fatalf("fields not retained: %+v", e)
	}
	var m FlowMetrics
	m.ServiceRole = "web"
	m.ParentComm = "sshd"
	if m.ServiceRole != "web" || m.ParentComm != "sshd" {
		t.Fatalf("metrics fields not retained: %+v", m)
	}
}

func TestEvent_L7Protocol(t *testing.T) {
	e := Event{L7Protocol: "http"}
	if e.L7Protocol != "http" {
		t.Fatalf("event L7Protocol not retained: %+v", e)
	}
	var m FlowMetrics
	m.L7Protocol = "tls"
	if m.L7Protocol != "tls" {
		t.Fatalf("metrics L7Protocol not retained: %+v", m)
	}
}
