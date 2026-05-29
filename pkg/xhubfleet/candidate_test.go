package xhubfleet

import (
	"strings"
	"testing"

	"github.com/xhelix/xhelix/pkg/baseline"
	"github.com/xhelix/xhelix/pkg/baselinehub"
)

// mkFullWindow constructs a baseline.Window with all feature maps set so
// the cohort folds in every dimension.
func mkFullWindow(binary string, children, endpoints, writes, ports map[string]uint64) *baseline.Window {
	return &baseline.Window{
		Binary:         binary,
		Children:       children,
		Endpoints:      endpoints,
		FileWrites:     writes,
		SensitivePaths: map[string]uint64{},
		BinarySHAs:     map[string]uint64{},
		ListenPorts:    ports,
	}
}

func ingestN(idx *RarityIndex, tags baselinehub.CohortTags, n int, w *baseline.Window) {
	for i := 0; i < n; i++ {
		host := "h-" + string(rune('A'+i%26)) + string(rune('0'+i/26))
		idx.Ingest(baselinehub.Upload{
			HostTag: host, Cohort: tags,
			Windows: []*baseline.Window{w},
		})
	}
}

// Below MinHosts: no candidate emitted.
func TestGenerateCandidates_BelowMinHostsRejected(t *testing.T) {
	idx := NewRarityIndex()
	tags := baselinehub.CohortTags{HostRole: "web", AppRole: "nginx", PackageOrigin: "apt"}
	ingestN(idx, tags, 3,
		mkFullWindow("nginx", map[string]uint64{"worker": 1}, nil, nil, nil))
	gates := DefaultCandidateGates() // MinHosts=5
	cands := GenerateCandidates(idx, gates)
	if len(cands) != 0 {
		t.Fatalf("expected 0 candidates below MinHosts, got %d", len(cands))
	}
}

// Quorum not met: no candidate emitted (no rows pass threshold).
func TestGenerateCandidates_QuorumNotMet(t *testing.T) {
	idx := NewRarityIndex()
	tags := baselinehub.CohortTags{HostRole: "web", AppRole: "nginx", PackageOrigin: "apt"}
	// 10 hosts. Each window's children is unique per host → no feature
	// will reach the 0.8 * 10 = 8 threshold.
	for i := 0; i < 10; i++ {
		host := "h" + string(rune('A'+i))
		uniqueChild := "child-" + string(rune('A'+i))
		idx.Ingest(baselinehub.Upload{
			HostTag: host, Cohort: tags,
			Windows: []*baseline.Window{mkFullWindow("nginx", map[string]uint64{uniqueChild: 1}, nil, nil, nil)},
		})
	}
	cands := GenerateCandidates(idx, DefaultCandidateGates())
	if len(cands) != 0 {
		t.Fatalf("expected 0 candidates when quorum unmet, got %d (rows=%+v)", len(cands), cands)
	}
}

// Quorum met across three classes: candidate with correct row mapping.
func TestGenerateCandidates_QuorumMetMultiClass(t *testing.T) {
	idx := NewRarityIndex()
	tags := baselinehub.CohortTags{
		HostRole: "web", AppRole: "nginx",
		OSFamily: "debian12", PackageOrigin: "apt", VersionFamily: "1.24.x",
	}
	w := mkFullWindow("nginx",
		map[string]uint64{"worker": 5},
		map[string]uint64{"10.0.0.0/24:443": 1},
		map[string]uint64{"/var/log/nginx/access.log": 1},
		map[string]uint64{"tcp:443": 1},
	)
	ingestN(idx, tags, 10, w)
	cands := GenerateCandidates(idx, DefaultCandidateGates())
	if len(cands) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(cands))
	}
	c := cands[0]
	if c.Binary != "nginx" {
		t.Fatalf("binary=%q", c.Binary)
	}
	if !c.QuorumMet {
		t.Fatalf("expected QuorumMet=true")
	}
	if c.TotalHosts != 10 {
		t.Fatalf("TotalHosts=%d", c.TotalHosts)
	}
	// Profile shape
	if c.Profile.Key.App != "nginx" {
		t.Fatalf("profile.key.app=%q", c.Profile.Key.App)
	}
	if c.Profile.Key.PackageOrigin != "apt" {
		t.Fatalf("profile.key.package_origin=%q", c.Profile.Key.PackageOrigin)
	}
	if len(c.Profile.Behavior.ExecAllowed) == 0 || c.Profile.Behavior.ExecAllowed[0] != "worker" {
		t.Fatalf("ExecAllowed=%v", c.Profile.Behavior.ExecAllowed)
	}
	if len(c.Profile.Behavior.UpstreamHosts) == 0 || c.Profile.Behavior.UpstreamHosts[0] != "10.0.0.0/24" {
		t.Fatalf("UpstreamHosts=%v", c.Profile.Behavior.UpstreamHosts)
	}
	if len(c.Profile.Behavior.WriteRoots) == 0 || c.Profile.Behavior.WriteRoots[0] != "/var/log/nginx" {
		t.Fatalf("WriteRoots=%v", c.Profile.Behavior.WriteRoots)
	}
	if len(c.Profile.Behavior.ListenPorts) == 0 || c.Profile.Behavior.ListenPorts[0] != 443 {
		t.Fatalf("ListenPorts=%v", c.Profile.Behavior.ListenPorts)
	}
	// Evidence carries at least one row per class
	classes := map[string]bool{}
	for _, r := range c.Evidence {
		classes[r.Class] = true
	}
	for _, must := range []string{"child", "endpoint", "file_write", "listen_port"} {
		if !classes[must] {
			t.Fatalf("evidence missing class %q (got %+v)", must, classes)
		}
	}
}

// PackageOrigin empty + RequireSamePackageOrigin=true: rejected and no candidate emitted.
func TestGenerateCandidates_PackageOriginGate(t *testing.T) {
	idx := NewRarityIndex()
	tags := baselinehub.CohortTags{HostRole: "web", AppRole: "nginx"} // PackageOrigin empty
	w := mkFullWindow("nginx", map[string]uint64{"worker": 1}, nil, nil, nil)
	ingestN(idx, tags, 10, w)
	gates := DefaultCandidateGates()
	cands := GenerateCandidates(idx, gates)
	if len(cands) != 0 {
		t.Fatalf("expected 0 candidates with empty package_origin + gate, got %d", len(cands))
	}
	// Same data with the gate disabled passes.
	gates.RequireSamePackageOrigin = false
	cands = GenerateCandidates(idx, gates)
	if len(cands) != 1 {
		t.Fatalf("expected 1 candidate with gate disabled, got %d", len(cands))
	}
}

// ValidateForSigning rejects an empty profile_id.
func TestValidateForSigning_RejectsEmptyProfileID(t *testing.T) {
	c := Candidate{QuorumMet: true}
	if err := ValidateForSigning(c); err == nil {
		t.Fatal("expected error for empty profile_id")
	}
}

// ValidateForSigning rejects quorum not met.
func TestValidateForSigning_RejectsNoQuorum(t *testing.T) {
	c := Candidate{QuorumMet: false}
	if err := ValidateForSigning(c); err == nil || !strings.Contains(err.Error(), "quorum") {
		t.Fatalf("expected quorum error, got %v", err)
	}
}

// GenerateCandidates returns rows in stable (cohort, binary) order.
func TestGenerateCandidates_StableOrdering(t *testing.T) {
	idx := NewRarityIndex()
	tagsA := baselinehub.CohortTags{HostRole: "web", AppRole: "nginx", PackageOrigin: "apt"}
	tagsB := baselinehub.CohortTags{HostRole: "db", AppRole: "mysql", PackageOrigin: "apt"}
	ingestN(idx, tagsA, 10, mkFullWindow("nginx", map[string]uint64{"worker": 1}, nil, nil, nil))
	ingestN(idx, tagsB, 10, mkFullWindow("mysqld", map[string]uint64{"helper": 1}, nil, nil, nil))

	var prev string
	for i := 0; i < 5; i++ {
		cands := GenerateCandidates(idx, DefaultCandidateGates())
		var buf strings.Builder
		for _, c := range cands {
			buf.WriteString(c.Cohort.String())
			buf.WriteString("|")
			buf.WriteString(c.Binary)
			buf.WriteString(";")
		}
		if i > 0 && buf.String() != prev {
			t.Fatalf("ordering not stable across runs:\n prev=%s\n cur=%s", prev, buf.String())
		}
		prev = buf.String()
	}
}
