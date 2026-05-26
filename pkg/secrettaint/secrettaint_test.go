package secrettaint

import (
	"sync"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

func TestStore_ObserveTouchPromotesClean(t *testing.T) {
	s := NewStore(0)
	now := time.Now().UTC()
	s.ObserveTouch(Touch{
		LineageID: 100, SecretClass: SecretSecretFile, Path: "/etc/shadow", At: now,
	})
	if got := s.StateForLineage(100); got != TaintSecretTouched {
		t.Errorf("after touch: state=%s, want secret_touched", got)
	}
	cls := s.ClassesForLineage(100)
	if len(cls) != 1 || cls[0] != SecretSecretFile {
		t.Errorf("classes=%v, want [secret_file]", cls)
	}
}

func TestStore_TouchAccumulatesClasses(t *testing.T) {
	s := NewStore(0)
	now := time.Now().UTC()
	s.ObserveTouch(Touch{LineageID: 1, SecretClass: SecretCloudCreds, At: now})
	s.ObserveTouch(Touch{LineageID: 1, SecretClass: SecretKubeToken, At: now})
	s.ObserveTouch(Touch{LineageID: 1, SecretClass: SecretCloudCreds, At: now}) // duplicate
	cls := s.ClassesForLineage(1)
	if len(cls) != 2 {
		t.Errorf("expected 2 unique classes, got %d: %v", len(cls), cls)
	}
}

func TestStore_PromotionMonotonic(t *testing.T) {
	s := NewStore(0)
	now := time.Now().UTC()
	s.ObserveTouch(Touch{LineageID: 7, SecretClass: SecretMetadata, At: now})

	s.PromoteOutboundRestricted(7, now, "novel dst")
	if got := s.StateForLineage(7); got != TaintOutboundRestricted {
		t.Errorf("after first promote: %s", got)
	}

	// Second promote (same level) is a no-op.
	s.PromoteOutboundRestricted(7, now, "another")
	if got := s.StateForLineage(7); got != TaintOutboundRestricted {
		t.Errorf("second promote shifted state: %s", got)
	}

	s.PromoteContainmentRequired(7, now, "secret+outbound+persistence")
	if got := s.StateForLineage(7); got != TaintContainmentRequired {
		t.Errorf("after containment promote: %s", got)
	}

	// Cannot regress.
	s.PromoteOutboundRestricted(7, now, "regress?")
	if got := s.StateForLineage(7); got != TaintContainmentRequired {
		t.Errorf("regression attempt landed: %s", got)
	}
}

func TestStore_PromoteCleanLineageIsNoop(t *testing.T) {
	// Promotion requires a prior touch. Clean lineage cannot be directly
	// promoted; this protects against bugs where the egressguard tries
	// to promote a lineage that never touched a secret.
	s := NewStore(0)
	s.PromoteOutboundRestricted(99, time.Now(), "test")
	if got := s.StateForLineage(99); got != TaintClean {
		t.Errorf("clean lineage was promoted: %s", got)
	}
}

func TestStore_InheritFromParent(t *testing.T) {
	s := NewStore(0)
	now := time.Now().UTC()
	s.ObserveTouch(Touch{LineageID: 10, SecretClass: SecretCloudCreds, At: now})

	s.InheritFromParent(10, 20) // child inherits
	if got := s.StateForLineage(20); got != TaintSecretTouched {
		t.Errorf("child state=%s, want secret_touched", got)
	}
	cls := s.ClassesForLineage(20)
	if len(cls) != 1 || cls[0] != SecretCloudCreds {
		t.Errorf("child classes=%v, want [cloud_creds]", cls)
	}
}

func TestStore_InheritFromCleanParentIsNoop(t *testing.T) {
	s := NewStore(0)
	s.InheritFromParent(1, 2)
	if got := s.StateForLineage(2); got != TaintClean {
		t.Errorf("child should stay clean, got %s", got)
	}
}

func TestStore_InheritFromHigherState(t *testing.T) {
	// Parent at OutboundRestricted → child inherits same level.
	s := NewStore(0)
	now := time.Now().UTC()
	s.ObserveTouch(Touch{LineageID: 1, SecretClass: SecretMetadata, At: now})
	s.PromoteOutboundRestricted(1, now, "parent")
	s.InheritFromParent(1, 2)
	if got := s.StateForLineage(2); got != TaintOutboundRestricted {
		t.Errorf("child should inherit OutboundRestricted, got %s", got)
	}
}

func TestStore_ChildAlreadyHigherStateNotRegressed(t *testing.T) {
	// Child is ContainmentRequired; parent is SecretTouched.
	// InheritFromParent must NOT regress the child.
	s := NewStore(0)
	now := time.Now().UTC()
	s.ObserveTouch(Touch{LineageID: 1, SecretClass: SecretSecretFile, At: now})
	s.ObserveTouch(Touch{LineageID: 2, SecretClass: SecretCloudCreds, At: now})
	s.PromoteContainmentRequired(2, now, "child reason")
	s.InheritFromParent(1, 2)
	if got := s.StateForLineage(2); got != TaintContainmentRequired {
		t.Errorf("child regressed to %s", got)
	}
}

func TestStore_ForgetClears(t *testing.T) {
	s := NewStore(0)
	now := time.Now().UTC()
	s.ObserveTouch(Touch{LineageID: 1, SecretClass: SecretMetadata, At: now})
	wasTainted := s.ForgetLineage(1, ForgetLineageExit)
	if !wasTainted {
		t.Error("ForgetLineage should report wasTainted=true")
	}
	if got := s.StateForLineage(1); got != TaintClean {
		t.Errorf("after forget: %s", got)
	}
}

func TestStore_ForgetCleanLineageReportsFalse(t *testing.T) {
	s := NewStore(0)
	if wasTainted := s.ForgetLineage(99, ForgetOperatorOverride); wasTainted {
		t.Error("forget on non-existent lineage should report wasTainted=false")
	}
}

func TestStore_SizeTracking(t *testing.T) {
	s := NewStore(0)
	now := time.Now().UTC()
	s.ObserveTouch(Touch{LineageID: 1, SecretClass: SecretMetadata, At: now})
	s.ObserveTouch(Touch{LineageID: 2, SecretClass: SecretCloudCreds, At: now})
	if s.Size() != 2 {
		t.Errorf("size=%d, want 2", s.Size())
	}
	s.ForgetLineage(1, ForgetLineageExit)
	if s.Size() != 1 {
		t.Errorf("after forget size=%d, want 1", s.Size())
	}
}

func TestStore_ConcurrentSafe(t *testing.T) {
	s := NewStore(0)
	const N = 100
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			t := Touch{LineageID: id, SecretClass: SecretCloudCreds, At: time.Now()}
			s.ObserveTouch(t)
			_ = s.StateForLineage(id)
			s.PromoteOutboundRestricted(id, time.Now(), "race-test")
			_ = s.ClassesForLineage(id)
		}(uint64(i + 1))
	}
	wg.Wait()
	if s.Size() != N {
		t.Errorf("after concurrent inserts: size=%d, want %d", s.Size(), N)
	}
}

func TestStore_Sweep(t *testing.T) {
	s := NewStore(1 * time.Hour).(*memStore)
	old := time.Now().UTC().Add(-2 * time.Hour)
	young := time.Now().UTC()
	s.ObserveTouch(Touch{LineageID: 1, SecretClass: SecretMetadata, At: old})
	s.ObserveTouch(Touch{LineageID: 2, SecretClass: SecretCloudCreds, At: young})
	reclaimed := s.Sweep(time.Now().UTC())
	if reclaimed != 1 {
		t.Errorf("sweep reclaimed %d, want 1", reclaimed)
	}
	if s.Size() != 1 {
		t.Errorf("after sweep: size=%d, want 1", s.Size())
	}
}

func TestClassifyEvent_CloudMetadata(t *testing.T) {
	ev := model.NewEvent("ebpf.net", model.SeverityInfo)
	ev.Tags["dst_ip"] = "169.254.169.254"
	c, ok := ClassifyEvent(ev)
	if !ok || c != SecretMetadata {
		t.Errorf("169.254.169.254 should classify as metadata, got %v %q", ok, c)
	}
}

func TestClassifyEvent_ProcEnviron(t *testing.T) {
	ev := model.NewEvent("procscrape", model.SeverityWarn)
	c, ok := ClassifyEvent(ev)
	if !ok || c != SecretProcEnviron {
		t.Errorf("procscrape should classify as proc_environ, got %v %q", ok, c)
	}
}

func TestClassifyEvent_FileReadShadow(t *testing.T) {
	ev := model.NewEvent("ebpf.file", model.SeverityInfo)
	ev.Tags["kind"] = "file_open"
	ev.Tags["path"] = "/etc/shadow"
	ev.Tags["mode"] = "read"
	c, ok := ClassifyEvent(ev)
	if !ok || c != SecretSecretFile {
		t.Errorf("/etc/shadow read should classify, got %v %q", ok, c)
	}
}

func TestClassifyEvent_CloudCreds(t *testing.T) {
	ev := model.NewEvent("ebpf.file", model.SeverityInfo)
	ev.Tags["kind"] = "file_open"
	ev.Tags["path"] = "/home/user/.aws/credentials"
	c, ok := ClassifyEvent(ev)
	if !ok || c != SecretCloudCreds {
		t.Errorf("aws creds read should classify, got %v %q", ok, c)
	}
}

func TestClassifyEvent_KubeToken(t *testing.T) {
	ev := model.NewEvent("ebpf.file", model.SeverityInfo)
	ev.Tags["kind"] = "file_open"
	ev.Tags["path"] = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	c, ok := ClassifyEvent(ev)
	if !ok || c != SecretKubeToken {
		t.Errorf("kube token read should classify, got %v %q", ok, c)
	}
}

func TestClassifyEvent_GenericNoMatch(t *testing.T) {
	ev := model.NewEvent("ebpf.file", model.SeverityInfo)
	ev.Tags["kind"] = "file_open"
	ev.Tags["path"] = "/home/user/document.txt"
	_, ok := ClassifyEvent(ev)
	if ok {
		t.Errorf("/home/user/document.txt should NOT classify as secret")
	}
}

func TestClassifyEvent_CredbrokerEvent(t *testing.T) {
	ev := model.NewEvent("credbroker", model.SeverityInfo)
	ev.Tags["class"] = "aws"
	c, ok := ClassifyEvent(ev)
	if !ok || c != SecretCloudCreds {
		t.Errorf("credbroker aws → cloud_creds; got %v %q", ok, c)
	}
}

func TestForgetReason_StringValues(t *testing.T) {
	cases := map[ForgetReason]string{
		ForgetLineageExit:      "lineage_exit",
		ForgetOperatorOverride: "operator_override",
		ForgetTTLExpiry:        "ttl_expiry",
	}
	for r, want := range cases {
		if got := r.String(); got != want {
			t.Errorf("ForgetReason(%d).String()=%q, want %q", r, got, want)
		}
	}
}

func TestTaintState_StringValues(t *testing.T) {
	cases := map[TaintState]string{
		TaintClean:               "clean",
		TaintSecretTouched:       "secret_touched",
		TaintOutboundRestricted:  "outbound_restricted",
		TaintContainmentRequired: "containment_required",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("TaintState(%d).String()=%q, want %q", s, got, want)
		}
	}
}
