package xhubfleet

import (
	"fmt"
	"sort"
	"strings"
)

// Weights are the integer point values for each scoring condition.
// All tunable; defaults match the plan in docs/XHUB_FLEET_INTELLIGENCE_PLAN.
type Weights struct {
	CommonInCohort       int // -30  behavior present in >50% of cohort
	PackageManagedSHA    int // -20  binary SHA matches peers (legit package)
	InSignedBRP          int // -40  behavior listed in operator-signed BRP
	RareEndpoint         int // +30  endpoint on ≤2/N hosts
	RareChild            int // +40  child process unusual for binary
	SensitiveAccess      int // +50  touched secret/data file
	PersistenceWrite     int // +70  wrote systemd/cron/ssh/pam path
	DangerousSyscall     int // +70  bpf, ptrace, mod_load, memfd
	NewBinaryHashTrusted int // +60  new SHA at trusted path
	SourceFromWeb        int // +30  lineage rooted at HTTP request
	SecretThenEgress     int // +90  secret-taint followed by egress
	BaselineLearningOnly int // +40  behavior appeared during observe only
}

func DefaultWeights() Weights {
	return Weights{
		CommonInCohort:       -30,
		PackageManagedSHA:    -20,
		InSignedBRP:          -40,
		RareEndpoint:         30,
		RareChild:            40,
		SensitiveAccess:      50,
		PersistenceWrite:     70,
		DangerousSyscall:     70,
		NewBinaryHashTrusted: 60,
		SourceFromWeb:        30,
		SecretThenEgress:     90,
		BaselineLearningOnly: 40,
	}
}

// Verdict is the bucket the integer score lands in.
type Verdict string

const (
	VerdictNormal     Verdict = "normal"
	VerdictWatch      Verdict = "watch"
	VerdictSuspicious Verdict = "suspicious"
	VerdictHigh       Verdict = "high"
	VerdictCritical   Verdict = "critical"
)

// ScoreToVerdict maps score → verdict per the plan:
//
//	<20    normal
//	20-49  watch
//	50-79  suspicious
//	80-119 high
//	120+   critical
func ScoreToVerdict(score int) Verdict {
	switch {
	case score < 20:
		return VerdictNormal
	case score < 50:
		return VerdictWatch
	case score < 80:
		return VerdictSuspicious
	case score < 120:
		return VerdictHigh
	default:
		return VerdictCritical
	}
}

// Contribution is one condition that fired during scoring with its delta.
type Contribution struct {
	Condition string
	Delta     int
	Detail    string // human-readable evidence ("php-fpm → bash seen on 1/50 hosts")
}

// Finding is the explainable result of scoring one (host, binary, behavior) triple.
type Finding struct {
	HostTag       string
	Binary        string
	Cohort        CohortKey
	Score         int
	Verdict       Verdict
	Contributions []Contribution
}

// ScoreContext gives the scorer everything it needs about ONE observed
// event/behavior to decide. Caller populates from the agent's report.
type ScoreContext struct {
	Cohort  *Cohort
	HostTag string
	Binary  string
	// Behaviour signals observed for this event:
	ChildProcess  string // "" if none
	EndpointKey   string // "cidr:port", "" if none
	FileWritePath string // "" if none
	SensitivePath string // "" if none — sensitive file the binary touched
	BinarySHA     string // exe_sha256 — "" if none
	ListenPort    string // "tcp:443" — "" if none
	// Flag-bit signals:
	DangerousSyscall     bool // bpf/ptrace/mod_load/memfd
	SourceFromWeb        bool // lineage rooted in HTTP request anchor
	SecretThenEgress     bool // secret-taint chained to outbound
	InSignedBRP          bool // matches operator-signed BRP behavior
	PackageManaged       bool // binary SHA from apt/rpm
	NewBinaryHashTrusted bool // new SHA at /usr/bin/* etc
	BaselineLearningOnly bool // baseline says "only seen during observe"
}

// CommonThreshold (50%) — behaviours present in this share of cohort
// hosts count as "common in cohort" and earn a noise discount.
const CommonThreshold = 0.5

// Score evaluates one context and returns a Finding with all contributing
// conditions. Pure function: same input → same output.
func Score(w Weights, ctx ScoreContext) Finding {
	f := Finding{
		HostTag: ctx.HostTag,
		Binary:  ctx.Binary,
	}
	if ctx.Cohort != nil {
		f.Cohort = ctx.Cohort.Key
	}
	add := func(cond, detail string, delta int) {
		if delta == 0 {
			return
		}
		f.Contributions = append(f.Contributions, Contribution{
			Condition: cond,
			Delta:     delta,
			Detail:    detail,
		})
		f.Score += delta
	}

	// Negative (noise-reducing) conditions
	if ctx.InSignedBRP {
		add("in_signed_brp", "behavior present in operator-signed BRP", w.InSignedBRP)
	}
	if ctx.PackageManaged {
		add("package_managed_sha", "binary SHA matches package manager", w.PackageManagedSHA)
	}
	// Determine "common in cohort" via rarity
	if ctx.Cohort != nil {
		hosts := ctx.Cohort.HostCount()
		rareCutoff := 2.0 / float64(maxInt(hosts, 1))
		if ctx.ChildProcess != "" {
			r := ctx.Cohort.RarityFraction(ClassChild, ctx.Binary, ctx.ChildProcess)
			switch {
			case r >= CommonThreshold:
				add("common_in_cohort:child", fmt.Sprintf("%s → %s seen on %.0f%% of cohort", ctx.Binary, ctx.ChildProcess, r*100), w.CommonInCohort)
			case r == 0:
				add("rare_child", fmt.Sprintf("%s → %s first-seen in cohort", ctx.Binary, ctx.ChildProcess), w.RareChild)
			case r <= rareCutoff:
				add("rare_child", fmt.Sprintf("%s → %s seen on %d/%d hosts", ctx.Binary, ctx.ChildProcess, int(r*float64(hosts)+0.5), hosts), w.RareChild)
			}
		}
		if ctx.EndpointKey != "" {
			r := ctx.Cohort.RarityFraction(ClassEndpoint, ctx.Binary, ctx.EndpointKey)
			switch {
			case r >= CommonThreshold:
				add("common_in_cohort:endpoint", fmt.Sprintf("%s contacted %s on %.0f%% of cohort", ctx.Binary, ctx.EndpointKey, r*100), w.CommonInCohort)
			case r == 0:
				add("rare_endpoint", fmt.Sprintf("%s → %s first-seen in cohort", ctx.Binary, ctx.EndpointKey), w.RareEndpoint)
			case r <= rareCutoff:
				add("rare_endpoint", fmt.Sprintf("%s → %s on %d/%d hosts", ctx.Binary, ctx.EndpointKey, int(r*float64(hosts)+0.5), hosts), w.RareEndpoint)
			}
		}
	}

	// Positive (alerting) conditions — independent of cohort
	if ctx.SensitivePath != "" {
		add("sensitive_access", fmt.Sprintf("touched %s", ctx.SensitivePath), w.SensitiveAccess)
	}
	if ctx.FileWritePath != "" && isPersistencePath(ctx.FileWritePath) {
		add("persistence_write", fmt.Sprintf("wrote to %s", ctx.FileWritePath), w.PersistenceWrite)
	}
	if ctx.DangerousSyscall {
		add("dangerous_syscall", "bpf/ptrace/mod_load/memfd executed", w.DangerousSyscall)
	}
	if ctx.NewBinaryHashTrusted {
		add("new_binary_hash_trusted", fmt.Sprintf("new SHA %s at trusted path", short(ctx.BinarySHA)), w.NewBinaryHashTrusted)
	}
	if ctx.SourceFromWeb {
		add("source_from_web", "lineage rooted at web request", w.SourceFromWeb)
	}
	if ctx.SecretThenEgress {
		add("secret_then_egress", "secret-taint followed by outbound", w.SecretThenEgress)
	}
	if ctx.BaselineLearningOnly {
		add("baseline_learning_only", "behavior appeared only during observe", w.BaselineLearningOnly)
	}

	f.Verdict = ScoreToVerdict(f.Score)
	sort.SliceStable(f.Contributions, func(i, j int) bool {
		return f.Contributions[i].Delta > f.Contributions[j].Delta
	})
	return f
}

func isPersistencePath(p string) bool {
	persistencePrefixes := []string{
		"/etc/cron.", "/etc/systemd/system/", "/etc/init.d/",
		"/etc/rc.local", "/etc/pam.d/", "/etc/ssh/",
		"/root/.ssh/", "/var/spool/cron/",
		"/etc/sudoers", "/boot/grub/",
	}
	for _, pref := range persistencePrefixes {
		if strings.HasPrefix(p, pref) {
			return true
		}
	}
	return false
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
