// Package config loads and validates the agent's YAML configuration.
//
// The config is read from a single file (default
// /etc/xhelix/xhelix.yaml). Three preset profiles are bundled to
// give operators a sensible starting point per workload class:
// desktop, server, container-host.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

// Config is the root document.
type Config struct {
	Preset      string            `yaml:"preset"`
	Logging     LoggingConfig     `yaml:"logging"`
	Agent       AgentConfig       `yaml:"agent"`
	Storage     StorageConfig     `yaml:"storage"`
	Ruleset     RulesetConfig     `yaml:"ruleset"`
	Sensors     SensorsConfig     `yaml:"sensors"`
	Alerts      AlertsConfig      `yaml:"alerts"`
	YARA        YARAConfig        `yaml:"yara"`
	SBOM        SBOMConfig        `yaml:"sbom"`
	Intel       IntelConfig       `yaml:"intel"`
	ML          MLConfig          `yaml:"ml"`
	Chain       ChainConfig       `yaml:"chain"`
	Posture     PostureConfig     `yaml:"posture"`
	SelfProtect SelfProtectConfig `yaml:"selfprotect"`
	Response    ResponseConfig    `yaml:"response"`
	Netban      NetbanConfig      `yaml:"netban"`
	Remediate   RemediateConfig   `yaml:"remediate"`
	Session     SessionConfig     `yaml:"session"`
	UI          UIConfig          `yaml:"ui"`
	Webhook     WebhookConfig     `yaml:"webhook"`
	Credbroker  CredbrokerConfig  `yaml:"credbroker"`
	SNICheck    SNICheckConfig    `yaml:"snicheck"`

	// v0.0.7: detect → snapshot → memscan → block → lockout → contain.
	Forensic       ForensicConfig       `yaml:"forensic"`
	MemScan        MemScanConfig        `yaml:"memscan"`
	Lockout        LockoutConfig        `yaml:"lockout"`
	ExecGuard      ExecGuardConfig      `yaml:"execguard"`
	HostQuarantine HostQuarantineConfig `yaml:"host_quarantine"`

	// v0.0.9: elite-tier detection — beaconing, tamper, kernel
	// integrity, threat intel, DNS exfil.
	Beacon      BeaconConfig      `yaml:"beacon"`
	TamperGuard TamperGuardConfig `yaml:"tamperguard"`
	KIntegrity  KIntegrityConfig  `yaml:"kintegrity"`
	ThreatFeed  ThreatFeedConfig  `yaml:"threatfeed"`
	DNSExfil    DNSExfilConfig    `yaml:"dnsexfil"`
	Baseline    BaselineConfig    `yaml:"baseline"`

	// Takeover — P-RF.9b daemon wiring for the planner pipeline.
	// Default: shadow mode (planner runs, Executor logs only).
	Takeover TakeoverConfig `yaml:"takeover"`

	// ProtectedServices — operator declares nginx/apache services
	// that should be locked down with Ring 1 + Ring 2.
	// See PROTECTED_SERVICES_TRAP.md.
	ProtectedServices ProtectedServicesConfig `yaml:"protected_services"`

	// Hardening — runtime hardening config (Phase C+G).
	// Includes egressguard mode + protected-role allowlist.
	Hardening HardeningConfig `yaml:"hardening"`

	// ForensicIngest — JSON-lines ingest path config (P-RF.9e).
	// (Named ForensicIngest, not Forensic, because the existing
	// Forensic field above is the /proc snapshot subsystem.)
	ForensicIngest ForensicIngestConfig `yaml:"forensic_ingest"`

	// Integrity — binary integrity baseline + verifier (B1+B2+B3).
	// Default off; operator opts in. See
	// docs/EGRESS_C2_DISARM_AND_BINARY_INTEGRITY_2026-05-22.md.
	Integrity IntegrityConfig `yaml:"integrity"`

	// Egress — Mode 1 (observe + classify) per
	// docs/EGRESS_C2_DISARM_AND_BINARY_INTEGRITY_2026-05-22.md §1.2.
	// Default off. Operator opts in by setting `egress.observe: true`.
	// Zero enforcement at this milestone — pure data layer that
	// classifies every outbound connect and records per-lineage
	// counters for the takeover scorer + operator CLI.
	Egress EgressConfig `yaml:"egress"`
}

// IntegrityConfig controls the B1+B2+B3 binary integrity subsystem.
type IntegrityConfig struct {
	// Enabled is the master toggle. Default false — operator opts in
	// (the first boot builds a baseline, which takes ~30s on a normal
	// host but is observable load).
	Enabled bool `yaml:"enabled"`
	// Mode: "off" / "detect" / "enforce". Default "detect" — log
	// mismatches but don't deny execve. Operator promotes to
	// "enforce" once they're satisfied with detect-mode signal.
	Mode string `yaml:"mode"`
	// BaselineDB is the SQLite path. Default /var/lib/xhelix/integrity-baseline.db.
	BaselineDB string `yaml:"baseline_db"`
	// AcceptTOFU controls TOFU policy for first-seen paths. Default
	// true (record and allow). False = deny anything not in baseline.
	AcceptTOFU bool `yaml:"accept_tofu"`
	// Paths overrides the built-in critical-path list. Empty = default.
	Paths []string `yaml:"paths"`
}

// EgressConfig controls the Mode-1 egress observer.
type EgressConfig struct {
	// Observe enables the destclass + per-lineage observer. Default
	// false — explicit opt-in.
	Observe bool `yaml:"observe"`
	// SampleTTL bounds retention of the per-lineage forensic sample.
	// Aggregate counters survive prune; only the recent-observation
	// slice is age-capped. Default 10m.
	SampleTTL time.Duration `yaml:"sample_ttl"`
	// MinFleetSeen — destinations seen by ≥ this many fleet hosts
	// graduate from "unknown" to "fleet_baseline". Default 3.
	MinFleetSeen int `yaml:"min_fleet_seen"`
	// CIDRFeedSync — if true, pull AWS / Cloudflare CIDRs from their
	// authoritative endpoints every 24h. Reduces "unknown" rate
	// significantly. Default false — requires outbound HTTPS from
	// the daemon (some ops postures forbid that).
	CIDRFeedSync bool `yaml:"cidr_feed_sync"`
}

// ForensicIngestConfig controls the directory tailer that consumes
// JSON-lines streams from the Ring 2 deception binaries.
// Disabled by default — operators opt in by setting enabled: true
// and pointing dir at a writable directory the deception binaries
// also write to.
type ForensicIngestConfig struct {
	Enabled      bool          `yaml:"enabled"`
	Dir          string        `yaml:"dir"`
	ScanInterval time.Duration `yaml:"scan_interval"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

// ProtectedServicesConfig wraps the operator's list of declared
// services. Empty by default; the daemon's Registry stays empty
// and xhelixctl protect list returns nothing — correct posture
// when no services are configured.
type ProtectedServicesConfig struct {
	Enabled  bool                          `yaml:"enabled"`
	Services []protectedsvc.ProtectedService `yaml:"services"`
}

// TakeoverConfig — pkg/daemon/wire knobs.
type TakeoverConfig struct {
	// Active flips authority: false (default) = shadow mode (log
	// only), true = planner ActionPlans actually run via Executor.
	Active bool `yaml:"active"`
	// TickInterval is how often the planner walks active lineages.
	// Default 5s.
	TickInterval time.Duration `yaml:"tick_interval"`
	// MinScore — sub-threshold scores produce no plan.
	// Default 50 (the planner's own default).
	MinScore int `yaml:"min_score"`
	// BastionAvailable + OffHostMirror — Layer-5 IsolateHost
	// preconditions. Both required for the planner to emit
	// contained-tier plans; otherwise it downgrades to isolated.
	BastionAvailable bool `yaml:"bastion_available"`
	OffHostMirror    bool `yaml:"off_host_mirror"`
}

// LoggingConfig configures the agent's own log output.
type LoggingConfig struct {
	Level       string `yaml:"level"`       // trace|debug|info|warn|error
	Format      string `yaml:"format"`      // text|json
	Destination string `yaml:"destination"` // stdout|stderr|<path>
}

// AgentConfig holds runtime knobs for the daemon process itself.
type AgentConfig struct {
	PIDFile           string        `yaml:"pid_file"`
	StateDir          string        `yaml:"state_dir"`
	LogDir            string        `yaml:"log_dir"`
	HeartbeatURL      string        `yaml:"heartbeat_url"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
}

// StorageConfig describes the hot/warm/cold tiers.
type StorageConfig struct {
	Hot  HotStorageConfig  `yaml:"hot"`
	Warm WarmStorageConfig `yaml:"warm"`
	Cold ColdStorageConfig `yaml:"cold"`
}

type HotStorageConfig struct {
	Path           string `yaml:"path"`
	RetentionHours uint   `yaml:"retention_hours"`
	MaxSizeMB      uint   `yaml:"max_size_mb"`
}

type WarmStorageConfig struct {
	Enabled bool   `yaml:"enabled"`
	Dir     string `yaml:"dir"`
}

type ColdStorageConfig struct {
	Enabled        bool   `yaml:"enabled"`
	S3Bucket       string `yaml:"s3_bucket"`
	ObjectLockDays uint   `yaml:"object_lock_days"`
}

// RulesetConfig points at bundled and custom rule sources.
type RulesetConfig struct {
	Bundled        string `yaml:"bundled"` // core|falco|none
	CustomDir      string `yaml:"custom_dir"`
	ReloadOnChange bool   `yaml:"reload_on_change"`
}

// CredbrokerConfig holds credbroker-side knobs. Sealed/honey behavior
// lives inside the broker itself; this struct adds the plaintext
// credential gate (P-PLAINTEXT) which has its own
// detect-vs-enforce switch.
type CredbrokerConfig struct {
	Plaintext PlaintextGateConfig `yaml:"plaintext"`
}

// PlaintextGateConfig governs the plaintext credential gate.
//
// Default behavior (detect-only): every open of a watched plaintext
// credential file emits an alert with the full reader lineage. The
// open is allowed.
//
// Enforce mode: opens by readers not in ExtraReaderComms /
// ExtraReaderImages (plus the baked-in defaults) are DENIED at
// FAN_OPEN_PERM time. Self-reads (UID-matching the file owner) are
// always allowed.
type PlaintextGateConfig struct {
	// Enforce flips kernel-side denial on. False = detect-only.
	Enforce bool `yaml:"enforce"`
	// ExtraPaths appends to DefaultPlaintextPaths(). Useful when
	// the host has site-specific credential locations.
	ExtraPaths []string `yaml:"extra_paths"`
	// ExtraReaderComms appends to DefaultPlaintextReaderComms().
	ExtraReaderComms []string `yaml:"extra_reader_comms"`
	// ExtraReaderImages appends to DefaultPlaintextReaderImages().
	ExtraReaderImages []string `yaml:"extra_reader_images"`
	// ExtraReaderImageGlobs appends to DefaultPlaintextReaderImageGlobs().
	ExtraReaderImageGlobs []string `yaml:"extra_reader_image_globs"`
}

// SNICheckConfig governs the SNI-required-for-TLS detector.
//
// Default: enabled in detect mode. Every outbound TLS connect that
// doesn't carry an SNI extension (after ~EvalDelay) produces a
// tls_no_sni alert. Allowlisted readers (systemd-resolved, apt,
// chronyd, etc.) are silenced.
type SNICheckConfig struct {
	// Enabled controls whether the detector runs at all.
	Enabled bool `yaml:"enabled"`
	// EvalDelay (e.g. "800ms") is the wait between connect and
	// SNI check. Zero = default (800ms).
	EvalDelay time.Duration `yaml:"eval_delay"`
	// TLSPorts overrides the default {443, 8443, 853, 993, 995} set.
	TLSPorts []uint16 `yaml:"tls_ports"`
	// AllowCIDRs exempts destination subnets known to legitimately
	// use bare-IP TLS (NTP, time servers, intentional IMDS allow).
	AllowCIDRs []string `yaml:"allow_cidrs"`
	// AllowReaderComms appends to the baked-in default set.
	AllowReaderComms []string `yaml:"allow_reader_comms"`
}

// SensorsConfig toggles each sensor plane.
type SensorsConfig struct {
	EBPF       EBPFSensorConfig       `yaml:"ebpf"`
	FIM        FIMSensorConfig        `yaml:"fim"`
	Decoys     DecoysSensorConfig     `yaml:"decoys"`
	NetIDS     NetIDSConfig           `yaml:"netids"`
	Identity   IdentityConfig         `yaml:"identity"`
	Memory     MemoryConfig           `yaml:"memory"`
	LSMAudit   LSMAuditConfig         `yaml:"lsm_audit"`
	Heartbeat  HeartbeatSensorConfig  `yaml:"heartbeat"`
	ProcScrape ProcScrapeSensorConfig `yaml:"procscrape"`
}

// ProcScrapeSensorConfig governs the /proc-scrape detector. The
// kernel hook lives in sensors/ebpf and emits proc_scrape events
// for every openat() against /proc/<pid>/{environ,maps,mem,auxv}.
// This config wires the userspace allowlist that turns the raw
// signal into a cred_proc_scrape verdict.
type ProcScrapeSensorConfig struct {
	// Enabled controls only the userspace enrichment. The eBPF
	// program itself is attached as part of sensors.ebpf when
	// EBPF.Enabled is true; disabling here means events flow
	// without the allowlist verdict (rules that test
	// cred_proc_scrape will simply never match).
	Enabled bool `yaml:"enabled"`
	// AllowlistFile overlays additional comm/image/glob entries
	// onto the baked-in default. Missing file is not an error.
	AllowlistFile string `yaml:"allowlist_file"`
}

type EBPFSensorConfig struct {
	Enabled       bool `yaml:"enabled"`
	RingbufSizeMB uint `yaml:"ringbuf_size_mb"`
}

type FIMSensorConfig struct {
	Enabled      bool     `yaml:"enabled"`
	WatchPaths   []string `yaml:"watch_paths"`
	WebRoots     []string `yaml:"web_roots"`
	PackageDiff  bool     `yaml:"package_diff"`
	SUIDBaseline bool     `yaml:"suid_baseline"`
}

type DecoysSensorConfig struct {
	Enabled        bool            `yaml:"enabled"`
	HoneyFiles     []HoneyFileSpec `yaml:"honey_files"`
	HoneyServices  []HoneyService  `yaml:"honey_services"`
	HoneyDNS       HoneyDNSConfig  `yaml:"honey_dns"`
	CanaryTokenURL string          `yaml:"canary_token_url"`
}

type HoneyFileSpec struct {
	Path          string   `yaml:"path"`
	Persona       string   `yaml:"persona"`
	AllowlistComm []string `yaml:"allowlist_comm,omitempty"`
}

type HoneyService struct {
	Port    int    `yaml:"port"`
	Persona string `yaml:"persona"`
	Bind    string `yaml:"bind"`
}

type HoneyDNSConfig struct {
	Hostnames []string `yaml:"hostnames"`
	PlantIn   []string `yaml:"plant_in"`
}

type NetIDSConfig struct {
	Enabled    bool              `yaml:"enabled"`
	Interfaces []string          `yaml:"interfaces"`
	DropMode   string            `yaml:"drop_mode"`
	Threat     ThreatIntelConfig `yaml:"threat_intel"`
}

type ThreatIntelConfig struct {
	SpamhausDROP bool       `yaml:"spamhaus_drop"`
	MISP         MISPConfig `yaml:"misp"`
}

type MISPConfig struct {
	URL string `yaml:"url"`
	Key string `yaml:"key"`
}

type IdentityConfig struct {
	Enabled bool `yaml:"enabled"`
}

type MemoryConfig struct {
	Enabled bool `yaml:"enabled"`
}

type LSMAuditConfig struct {
	Enabled bool `yaml:"enabled"`
}

type HeartbeatSensorConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
}

// AlertsConfig configures the alert bus and its sinks.
type AlertsConfig struct {
	Sinks             []SinkConfig    `yaml:"sinks"`
	SeverityThreshold string          `yaml:"severity_threshold"`
	RateLimit         RateLimitConfig `yaml:"rate_limit"`
}

type SinkConfig struct {
	Kind         string        `yaml:"kind"`
	Path         string        `yaml:"path,omitempty"`
	URL          string        `yaml:"url,omitempty"`
	Facility     string        `yaml:"facility,omitempty"`
	TimeoutSec   int           `yaml:"timeout_sec,omitempty"`
	RotateSizeMB uint          `yaml:"rotate_size_mb,omitempty"`
	Keep         uint          `yaml:"keep,omitempty"`
	Timeout      time.Duration `yaml:"-"`
}

type RateLimitConfig struct {
	PerRulePerMinute uint `yaml:"per_rule_per_minute"`
	GlobalPerSecond  uint `yaml:"global_per_second"`
}

type YARAConfig struct {
	Enabled  bool   `yaml:"enabled"`
	RulesDir string `yaml:"rules_dir"`
}

type SBOMConfig struct {
	Enabled      bool   `yaml:"enabled"`
	BaselinePath string `yaml:"baseline_path"`
}

type IntelConfig struct {
	Enabled bool `yaml:"enabled"`
}

type MLConfig struct {
	Enabled   bool    `yaml:"enabled"`
	Window    int     `yaml:"window"`
	Threshold float64 `yaml:"threshold"`
}

type ChainConfig struct {
	Enabled bool   `yaml:"enabled"`
	Dir     string `yaml:"dir"`
	KeyPath string `yaml:"key_path"`
	// MaxBatches caps the number of *.bin batch files kept under Dir.
	// 0 = use default (2000). Negative = unbounded (legacy unsafe;
	// destroyed disk in 2026-05-24 incident — 5571 files / 20GB in 28h).
	MaxBatches int `yaml:"max_batches"`
}

// HardeningConfig is the operator surface for the runtime hardening
// substrate (Phase C egressguard + Phase G daemon hardening). All
// fields default to safe values; the daemon ships with everything in
// the most permissive setting and operators promote per-feature.
type HardeningConfig struct {
	Egressguard EgressguardConfig `yaml:"egressguard"`
	// Seccomp controls the daemon's self-applied seccomp allowlist
	// (Phase G.2). Default mode = "off" (no filter). Operator promotes
	// to "audit" (filter installed, denied syscalls logged to
	// /var/log/audit/audit.log but not blocked) for 24-48h soak,
	// inspects the audit log for any denied syscall, then promotes
	// to "enforce" (denied syscalls return EPERM; daemon will die if
	// any required syscall is denied). High self-DoS risk — do NOT
	// enable enforce without audit-mode soak.
	Seccomp SeccompConfig `yaml:"seccomp"`
	// Landlock controls the daemon's Linux Landlock filesystem ACL
	// (Phase G.3). Default mode = "off"; promote to "dry-run" for
	// preview then "enforce" to actually restrict.
	Landlock LandlockConfig `yaml:"landlock"`
	// BPFLSM controls the Phase I synchronous-deny BPF-LSM program.
	// HARD prerequisite: kernel cmdline must include `bpf` in
	// lsm=...; xhelix probes /sys/kernel/security/lsm at startup
	// and refuses to load if absent. Default mode = "off".
	BPFLSM BPFLSMConfig `yaml:"bpflsm"`
}

// BPFLSMConfig controls the daemon Phase I BPF-LSM program.
type BPFLSMConfig struct {
	// Mode is "off" | "load" | "enforce". Empty = "off".
	// load: program loaded but NOT attached (operator preview)
	// enforce: attached to security_bprm_check; synchronous deny live
	Mode string `yaml:"mode"`
	// DenyPaths is the initial deny-list seeded into the kernel map
	// on startup. Operator can add/remove at runtime via xhelixctl.
	DenyPaths []string `yaml:"deny_paths"`
	// ObjectPath is where to find the compiled BPF-LSM object.
	// Default: /usr/lib/xhelix/xhelix-lsm.o
	ObjectPath string `yaml:"object_path"`
}

// SeccompConfig controls the daemon self-seccomp filter (Phase G.2).
type SeccompConfig struct {
	// Mode is "off" | "audit" | "enforce". Empty = "off".
	Mode string `yaml:"mode"`
}

// LandlockConfig controls the daemon filesystem-ACL via Linux Landlock
// (Phase G.3). Default mode = "off" (no restriction). Operator promotes
// to "dry-run" (log what would be allowed; no actual restriction) for
// preview, then "enforce" (irreversible filesystem restriction —
// daemon and all children can only read/write paths in the policy).
// IMPORTANT: enforce mode is irreversible per-process; if the allowlist
// is wrong, the daemon will fail to write its own state.
type LandlockConfig struct {
	// Mode is "off" | "dry-run" | "enforce". Empty = "off".
	Mode string `yaml:"mode"`
	// ExtraReadOnly extends the default read-only allowlist (operator-
	// supplied paths added on top of DefaultPolicy().ReadOnly).
	ExtraReadOnly []string `yaml:"extra_read_only"`
	// ExtraReadWrite extends the default read-write allowlist.
	// Use with care — every entry expands the daemon's write surface.
	ExtraReadWrite []string `yaml:"extra_read_write"`
}

// EgressguardConfig controls the per-event egress decision plane.
//
// Mode rollout discipline (build spec §0 lock):
//   observe  — classify only, no logging or kernel push (default)
//   shadow   — log would-be denies; no kernel push; safe for FP soak
//   enforce  — push denies to kernel backend; production gate
//
// Operator promotes observe → shadow → enforce, with a soak between
// each stage. Auto-rollback on FP budget breach is a Phase E.1 feature.
type EgressguardConfig struct {
	// Mode is "observe" | "shadow" | "enforce". Empty = "observe".
	Mode string `yaml:"mode"`
	// ProtectedRoles overrides the default protected-role allowlist
	// (nginx-*, apache-*, mysql-*, sshd-*, etc.). When non-empty,
	// replaces the default. When empty, the default is used.
	ProtectedRoles []string `yaml:"protected_roles"`
}

type PostureConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
}

type SelfProtectConfig struct {
	Enabled   bool `yaml:"enabled"`
	Immutable bool `yaml:"immutable"`
	Watchdog  bool `yaml:"watchdog"`
	Integrity bool `yaml:"integrity"`
}

// ResponseConfig wires the active-response engine.
//
// The engine subscribes to alerts and translates them to per-rule
// actions (quarantine, netban, remediate, webhook). Disabled by
// default — operators must opt in.
type ResponseConfig struct {
	Enabled bool `yaml:"enabled"`
	// SoakDays gates auto-quarantine: a rule must run this many
	// consecutive days without an operator-marked false positive
	// before it can take destructive action. Default 30.
	SoakDays uint `yaml:"soak_days"`
	// MonitorMode, when true, runs the engine observe-only — every
	// per-alert action is masked to ActionLog|ActionWebhook before
	// dispatch. Use this for learning-mode deployments where you
	// want to see what xhelix would have done without it actually
	// SIGSTOPping production processes. Default false (enforce).
	MonitorMode bool `yaml:"monitor_mode"`

	// EnforceRules is an operator-supplied list of rule IDs that
	// bypass MonitorMode and execute their full destructive action
	// mask on fire. The intended use is graduating individual
	// Class-1 hard-invariant rules out of monitor mode after
	// operators have verified the rule has zero FPs on this
	// specific host class.
	//
	// Empty = no rules promoted (every rule still respects
	// MonitorMode). Promotion is a per-rule operator decision
	// done via `xhelixctl rules promote <rule_id>`.
	//
	// Safety: even promoted rules still respect the autobaseline
	// gates (baseline_observing strips destructive actions; only
	// when autobaseline is sealed AND lineage hits baseline_known
	// is the rule's destructive mask stripped). The promotion
	// only bypasses the GLOBAL MonitorMode flag.
	EnforceRules []string `yaml:"enforce_rules"`
}

// NetbanConfig configures the IP banning subsystem.
type NetbanConfig struct {
	Enabled     bool `yaml:"enabled"`
	UseNFTables bool `yaml:"use_nftables"`
}

// RemediateConfig sets up the file-restore subsystem.
type RemediateConfig struct {
	Enabled       bool     `yaml:"enabled"`
	BackupDir     string   `yaml:"backup_dir"`
	QuarantineDir string   `yaml:"quarantine_dir"`
	BackupPaths   []string `yaml:"backup_paths"`
}

// SessionConfig toggles the SSH session tracker.
type SessionConfig struct {
	Enabled             bool `yaml:"enabled"`
	MaxEventsPerSession int  `yaml:"max_events_per_session"`
}

// UIConfig is the web dashboard's protection layer.
type UIConfig struct {
	Enabled          bool     `yaml:"enabled"`
	Bind             string   `yaml:"bind"` // 0.0.0.0:18443
	TLSEnabled       bool     `yaml:"tls_enabled"`
	TLSCert          string   `yaml:"tls_cert"`
	TLSKey           string   `yaml:"tls_key"`
	HTTPRedirect     bool     `yaml:"http_redirect"` // listen on :18080 too
	HTTPRedirectAddr string   `yaml:"http_redirect_addr"`
	AllowIPs         []string `yaml:"allow_ips"`
	TrustedProxies   []string `yaml:"trusted_proxies"`
	AutoDetectSSH    bool     `yaml:"auto_detect_ssh"`
	TokenFile        string   `yaml:"token_file"`
	AuditLog         string   `yaml:"audit_log"`
	RateLimit        int      `yaml:"rate_limit_per_second"`
	TrustForwarded   bool     `yaml:"trust_forwarded_for"`
}

// WebhookConfig is a single webhook endpoint for response.
type WebhookConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
}

// ForensicConfig configures the pre-kill evidence capture.
type ForensicConfig struct {
	Enabled     bool   `yaml:"enabled"`
	EvidenceDir string `yaml:"evidence_dir"`
}

// MemScanConfig toggles in-memory pattern scanning of suspect pids.
type MemScanConfig struct {
	Enabled bool `yaml:"enabled"`
	// MaxRegionMB caps a single mapping read. 0 = 64 MB default.
	MaxRegionMB int `yaml:"max_region_mb"`
}

// LockoutConfig toggles account-lockout actions.
type LockoutConfig struct {
	Enabled bool `yaml:"enabled"`
}

// ExecGuardConfig configures the fanotify exec-deny guard.
//
// MountPoints defaults to {"/"}. DenyPaths is the deny-list; when
// empty, execguard.DefaultRules() is used (denies /tmp, /var/tmp,
// /dev/shm, /proc/self/fd/*).
type ExecGuardConfig struct {
	Enabled     bool     `yaml:"enabled"`
	MountPoints []string `yaml:"mount_points"`
	DenyPaths   []string `yaml:"deny_paths"`
}

// HostQuarantineConfig configures the response action that isolates
// the host from the network. AllowIPs is the management allow-list
// — typically the operator's SSH client IP.
type HostQuarantineConfig struct {
	Enabled  bool     `yaml:"enabled"`
	AllowIPs []string `yaml:"allow_ips"`
}

// BeaconConfig tunes the C2 beaconing detector.
type BeaconConfig struct {
	Enabled        bool     `yaml:"enabled"`
	MinSamples     int      `yaml:"min_samples"`
	MaxJitterCV    float64  `yaml:"max_jitter_cv"`
	MinSpanSeconds int      `yaml:"min_span_seconds"`
	AllowList      []string `yaml:"allow_list"`
}

// TamperGuardConfig tunes the sensor self-protection watchdog.
type TamperGuardConfig struct {
	Enabled         bool `yaml:"enabled"`
	IntervalSeconds int  `yaml:"interval_seconds"`
	CheckAuditd     bool `yaml:"check_auditd"`
}

// KIntegrityConfig tunes the kernel-integrity checker.
type KIntegrityConfig struct {
	Enabled         bool `yaml:"enabled"`
	IntervalSeconds int  `yaml:"interval_seconds"`
}

// ThreatFeedConfig tunes the public IP-feed fetcher (Spamhaus etc.)
// — distinct from the existing ThreatIntelConfig which configures the
// internal NetIDS intel manager.
type ThreatFeedConfig struct {
	Enabled      bool               `yaml:"enabled"`
	RefreshHours int                `yaml:"refresh_hours"`
	AllowOffline bool               `yaml:"allow_offline"`
	ExtraSources []ThreatFeedSource `yaml:"extra_sources"`
}

type ThreatFeedSource struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

// BaselineConfig configures per-binary feature aggregation. The
// aggregator records hourly windows of syscall histograms, network
// endpoints, file writes, and child processes per binary. The output
// is written as JSONL (gzip-rotated daily) under StoreDir, and is
// the foundation for any future ML/baseline scoring.
type BaselineConfig struct {
	Enabled          bool     `yaml:"enabled"`
	StoreDir         string   `yaml:"store_dir"`           // default <state_dir>/baseline
	KeepHours        int      `yaml:"keep_hours"`          // 0 = 2
	MaxKeysPerWindow int      `yaml:"max_keys_per_window"` // 0 = 64
	IgnoreBinaries   []string `yaml:"ignore_binaries"`     // skip these comms/images
	RetentionDays    int      `yaml:"retention_days"`      // 0 = 30; 0 disables prune

	// Phase 2: scoring on top of the baseline.
	Scoring BaselineScoringConfig `yaml:"scoring"`

	// Phase 3: optional fleet hub upload.
	Hub BaselineHubConfig `yaml:"hub"`
}

// BaselineScoringConfig tunes the set-diff scorer + rate detector.
type BaselineScoringConfig struct {
	Enabled            bool `yaml:"enabled"`
	WarmupHours        int  `yaml:"warmup_hours"`         // 0 = 24
	HysteresisN        int  `yaml:"hysteresis_n"`         // 0 = 2
	MinFeatureClasses  int  `yaml:"min_feature_classes"`  // 0 = 1
	LookbackDays       int  `yaml:"lookback_days"`        // 0 = 7
	RebuildHours       int  `yaml:"rebuild_hours"`        // 0 = 6
	RateAlphaPercent   int  `yaml:"rate_alpha_percent"`   // 0 = 10  (alpha = 0.10)
	RateSigmaThreshold int  `yaml:"rate_sigma_threshold"` // 0 = 5
	RateMinHistory     int  `yaml:"rate_min_history"`     // 0 = 24
	RateMinEvents      int  `yaml:"rate_min_events"`      // 0 = 100
}

// BaselineHubConfig configures the agent's upload to a fleet hub.
// Empty URL = no upload, agent runs standalone.
type BaselineHubConfig struct {
	URL                   string `yaml:"url"`                      // e.g. https://xhub.example.com:18444
	UploadIntervalMin     int    `yaml:"upload_interval_min"`      // 0 = 5
	HostTag               string `yaml:"host_tag"`                 // e.g. "web-prod-01"
	RoleTag               string `yaml:"role_tag"`                 // e.g. "web", "db"
	AuthToken             string `yaml:"auth_token"`               // bearer
	TLSInsecureSkipVerify bool   `yaml:"tls_insecure_skip_verify"` // dev only
	QueueDir              string `yaml:"queue_dir"`                // default <state_dir>/hubqueue
}

// DNSExfilConfig tunes the DNS-tunnel detector.
type DNSExfilConfig struct {
	Enabled             bool    `yaml:"enabled"`
	WindowSeconds       int     `yaml:"window_seconds"`
	MinQueriesPerWindow int     `yaml:"min_queries_per_window"`
	MaxLabelLen         float64 `yaml:"max_label_len"`
	MaxEntropy          float64 `yaml:"max_entropy"`
	MaxTxtFraction      float64 `yaml:"max_txt_fraction"`
}

// Default returns a Config with safe out-of-the-box values.
func Default() Config {
	return Config{
		Preset: "server",
		Logging: LoggingConfig{
			Level:       "info",
			Format:      "text",
			Destination: "stdout",
		},
		Agent: AgentConfig{
			PIDFile:           "/run/xhelix/xhelix.pid",
			StateDir:          "/var/lib/xhelix",
			LogDir:            "/var/log/xhelix",
			HeartbeatInterval: time.Second,
		},
		Storage: StorageConfig{
			Hot: HotStorageConfig{
				Path:           "/var/lib/xhelix/hot.db",
				RetentionHours: 24,
				MaxSizeMB:      2048,
			},
		},
		Ruleset: RulesetConfig{
			Bundled:        "core",
			CustomDir:      "/etc/xhelix/rules.d",
			ReloadOnChange: true,
		},
		Sensors: SensorsConfig{
			Heartbeat: HeartbeatSensorConfig{
				Enabled:  true,
				Interval: time.Second,
			},
			ProcScrape: ProcScrapeSensorConfig{
				// Detect-only ships on by default; the rule
				// (ruleset/core/cred_proc_scrape.yaml) is
				// medium-sev with no auto-response.
				Enabled:       true,
				AllowlistFile: "/etc/xhelix/procscrape-allowlist.conf",
			},
		},
		SNICheck: SNICheckConfig{
			Enabled: true,
		},
		Alerts: AlertsConfig{
			Sinks: []SinkConfig{
				{Kind: "stdout"},
			},
			SeverityThreshold: "notice",
			RateLimit: RateLimitConfig{
				PerRulePerMinute: 60,
				GlobalPerSecond:  500,
			},
		},
	}
}

// Load reads a YAML config from disk and merges it over the default.
//
// If path is empty or the file is missing, Default() is returned
// without error so the agent can boot in development without a
// config file.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	cfg = ApplyPreset(cfg)
	return cfg, nil
}
