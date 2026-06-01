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
