package verify

import "strings"

// Domains additional to PathClassifier (which lives in engine.go).
// Each follows the same contract: read-only Input, return (score, reason).
// Positive scores increase suspicion; negative scores attenuate it.

// PhaseCorrelation weights the actor's lifecycle phase. The same write
// is far less suspicious during normal bootstrap or a known reload than
// during steady-state or right after a crash.
//
// Phase weights:
//
//	bootstrap → -1.5  (broad behavior is normal)
//	reload    → -1.0  (config re-read window)
//	steady    →  0    (no adjustment)
//	degraded  → +2.0  (attackers love crash-recovery races)
type PhaseCorrelation struct{}

func (PhaseCorrelation) Name() string { return "phase_correlation" }

func (PhaseCorrelation) Score(in Input) (float64, string) {
	switch in.Phase {
	case "bootstrap":
		return -1.5, "bootstrap window"
	case "reload":
		return -1.0, "reload window"
	case "degraded":
		return 2.0, "degraded phase (crash-recovery)"
	}
	return 0, ""
}

// SourceLineage weights the originating anchor type. Operator sessions
// (ssh, sudo, pam) are far less suspicious than host-anchored activity
// that has no human in the loop.
//
// Anchor weights:
//
//	(missing)    →  0    (host activity baseline)
//	host         → +1.0  (no operator at all)
//	systemd      →  0    (service-managed)
//	cron         →  0    (scheduled task)
//	pam, sudo, su, ssh → -2.0 (interactive operator session)
type SourceLineage struct{}

func (SourceLineage) Name() string { return "source_lineage" }

func (SourceLineage) Score(in Input) (float64, string) {
	if in.SourceAnchorID == 0 {
		return 0, ""
	}
	switch in.AnchorKind {
	case "pam", "sudo", "su", "ssh", "sshd":
		return -2.0, "operator session anchor (" + in.AnchorKind + ")"
	case "host", "":
		return 1.0, "host-anchored (no operator session)"
	case "systemd", "cron":
		return 0, in.AnchorKind + "-anchored"
	}
	return 0, ""
}

// IntegrityHash applies the pkg/integrity Authentic-upgrade verdict.
// When the writer was confirmed by T1-T5 as a real package transaction,
// the write is highly likely to be legitimate — large negative weight.
type IntegrityHash struct{}

func (IntegrityHash) Name() string { return "integrity_hash" }

func (IntegrityHash) Score(in Input) (float64, string) {
	if in.IntegrityAuthentic {
		return -3.0, "authentic upgrade verdict (pkg/integrity)"
	}
	return 0, ""
}

// BehaviorHistory consults the autobaseline aggregator's IsKnown verdict.
// If the host has previously observed this (image, behavior) pair
// without incident, attenuate the score.
type BehaviorHistory struct{}

func (BehaviorHistory) Name() string { return "behavior_history" }

func (BehaviorHistory) Score(in Input) (float64, string) {
	if in.BaselineKnown {
		return -2.0, "behavior matches sealed host baseline"
	}
	return 0, ""
}

// NetworkNovelty weights the egress-observer classification. Only fires
// on net_connect actions; file writes return 0.
//
// Classes:
//
//	known_upstream → -1.0 (already declared upstream)
//	novel_external → +2.0 (first-seen external destination)
//	rare_endpoint  → +1.0 (uncommon endpoint within the app's history)
type NetworkNovelty struct{}

func (NetworkNovelty) Name() string { return "network_novelty" }

func (NetworkNovelty) Score(in Input) (float64, string) {
	if in.Facts.Action != "net_connect" {
		return 0, ""
	}
	switch in.DestClass {
	case "known_upstream":
		return -1.0, "destination is declared upstream"
	case "novel_external":
		return 2.0, "novel external destination"
	case "rare_endpoint":
		return 1.0, "rare endpoint for app"
	}
	return 0, ""
}

// CrossApp scores the (actor_app, target_app) edge. Web/DB tier topology
// is well-defined: nginx legitimately talks to php-fpm; php-fpm to mysql;
// almost nothing legitimately talks shell-out from a web/db role.
//
// Known-good edges attenuate the score; novel edges where the actor is
// a "web" role and the target is a shell or interpreter compound the
// existing role-invariant signal (defense in depth).
//
// Edge table:
//
//	nginx     → php-fpm, fastcgi      attenuate -1.5
//	nginx     → app, node, java       attenuate -1.0
//	php-fpm   → mysql, mariadb, redis attenuate -1.5
//	apache    → php-fpm, app          attenuate -1.0
//	app/web   → sh, bash, python      penalty +3.0 (shell-out from web tier)
//	web tier  → mysql/postgres        attenuate -1.0
//	(unknown) → (unknown)             no signal (0)
type CrossApp struct{}

func (CrossApp) Name() string { return "cross_app" }

func (CrossApp) Score(in Input) (float64, string) {
	actor := in.ActorApp
	target := in.TargetApp
	if actor == "" || target == "" {
		return 0, ""
	}
	// Known-good downstream edges per actor role.
	allowed := map[string]map[string]float64{
		"nginx": {
			"php-fpm":   -1.5,
			"fastcgi":   -1.5,
			"app":       -1.0,
			"node":      -1.0,
			"java":      -1.0,
			"haproxy":   -1.0,
			"varnish":   -1.0,
			"mysql":     -1.0,
			"mariadb":   -1.0,
			"postgres":  -1.0,
			"redis":     -1.0,
			"memcached": -1.0,
		},
		"apache": {
			"php-fpm":  -1.5,
			"app":      -1.0,
			"mysql":    -1.0,
			"mariadb":  -1.0,
			"postgres": -1.0,
		},
		"php-fpm": {
			"mysql":     -1.5,
			"mariadb":   -1.5,
			"postgres":  -1.5,
			"redis":     -1.5,
			"memcached": -1.0,
			"mongodb":   -1.0,
			"app":       -1.0,
		},
		"haproxy": {
			"nginx":    -1.0,
			"apache":   -1.0,
			"app":      -1.0,
			"node":     -1.0,
		},
	}
	// Web/DB tier roles attempting to exec a shell or interpreter:
	// compound penalty (BRP role invariant already hard-denies; this
	// adds verifier-side score so the audit trail records it).
	shellTargets := map[string]bool{
		"sh": true, "bash": true, "dash": true, "zsh": true,
		"python": true, "perl": true, "ruby": true, "node": false, // node is a normal target
	}
	webTier := map[string]bool{
		"nginx": true, "apache": true, "php-fpm": true,
		"mysql": true, "mariadb": true, "postgres": true, "redis": true,
	}
	if webTier[actor] && shellTargets[target] && target != "node" {
		return 3.0, "web/db tier shell-out (" + actor + " → " + target + ")"
	}
	if downstream, ok := allowed[actor]; ok {
		if w, ok := downstream[target]; ok {
			if in.EdgeAllowed {
				// Operator-signed edge corroborates the built-in table.
				return w - 2.0, "signed edge + known " + actor + " → " + target
			}
			return w, "known edge " + actor + " → " + target
		}
		// Same actor, unknown target — small positive signal unless an
		// operator-signed edge explicitly allows this pair.
		if in.EdgeAllowed {
			return -1.0, "signed edge: " + actor + " → " + target
		}
		return 0.5, "unknown edge from " + actor + " → " + target
	}
	// Actor not in built-in table, but operator signed an edge for them.
	if in.EdgeAllowed {
		return -1.0, "signed operator edge: " + actor + " → " + target
	}
	return 0, ""
}

// SecretContext scores events whose actor lineage has touched secrets.
// The single highest-leverage detection domain — turns secret theft
// into a chain visible to the verifier instead of an isolated event.
//
// State weights (cumulative with class weight below):
//
//	secret_touched         → +1.0   actor touched secrets recently
//	outbound_restricted    → +2.5   already restricted; further actions are high-risk
//	containment_required   → +5.0   force-promote anything from this lineage
//
// Class-specific bonuses (per touched class):
//
//	metadata               → +2.0   IMDS abuse is canonical SSRF/token-theft
//	cloud_creds            → +1.5   AWS/GCP/Azure long-lived creds
//	kube_token             → +1.5   K8s service-account token
//	workload_identity      → +1.5   cloud-init sensitive material
//	proc_environ           → +1.0   classic env scrape pattern
//	secret_file            → +1.0   /etc/shadow, SSH keys, sudoers
//	browser_session        → +0.8   form-grabber / extension theft
//	git_token / api_key    → +0.5   developer-machine theft
//	env / token / session  → +0.3   generic
//
// Cap at +6.0 to avoid score explosion when many classes touched.
//
// Action-specific bonuses (compound on the above):
//
//	net_connect after touch  → +1.5   "theft via egress" chain
//	exec after touch         → +1.0   "theft via spawned tool" chain
//	file_write to /etc/cron* → +2.0   "theft + persistence" worst case
//
// Note: clean lineage (taint=="") returns 0; no penalty for the absence
// of taint. The contribution is purely additive when taint exists.
type SecretContext struct{}

func (SecretContext) Name() string { return "secret_context" }

func (SecretContext) Score(in Input) (float64, string) {
	if in.SecretTaint == "" || in.SecretTaint == "clean" {
		return 0, ""
	}
	var score float64
	var reasons []string

	// State weight.
	switch in.SecretTaint {
	case "secret_touched":
		score += 1.0
		reasons = append(reasons, "lineage touched secrets")
	case "outbound_restricted":
		score += 2.5
		reasons = append(reasons, "lineage outbound-restricted")
	case "containment_required":
		score += 5.0
		reasons = append(reasons, "lineage requires containment")
	}

	// Class-specific weight.
	classWeight := 0.0
	for _, c := range in.SecretClasses {
		switch c {
		case "metadata":
			classWeight += 2.0
		case "cloud_creds", "kube_token", "workload_identity":
			classWeight += 1.5
		case "proc_environ", "secret_file":
			classWeight += 1.0
		case "browser_session":
			classWeight += 0.8
		case "git_token", "api_key":
			classWeight += 0.5
		default:
			classWeight += 0.3
		}
	}
	if classWeight > 0 {
		if classWeight > 4.0 {
			classWeight = 4.0 // cap class contribution
		}
		score += classWeight
		reasons = append(reasons, "touched classes weighted")
	}

	// Action-specific compound bonuses.
	if in.Facts.Action == "net_connect" {
		score += 1.5
		reasons = append(reasons, "outbound after secret touch")
	}
	if in.Facts.Action == "exec" || in.Facts.Action == "process_spawn" {
		score += 1.0
		reasons = append(reasons, "exec after secret touch")
	}
	if isWriteToPersistencePath(in.Facts.Path) {
		score += 2.0
		reasons = append(reasons, "persistence write after secret touch")
	}

	// Overall cap.
	if score > 8.0 {
		score = 8.0
	}
	return score, strings.Join(reasons, "; ")
}

// isWriteToPersistencePath is a narrow helper — checks only the
// highest-value persistence surfaces. Asset taxonomy covers the broader
// set; this one focuses on the "secret + persistence" attack pattern.
func isWriteToPersistencePath(path string) bool {
	if path == "" {
		return false
	}
	for _, prefix := range []string{
		"/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/",
		"/etc/crontab", "/var/spool/cron/",
		"/etc/systemd/system/", "/etc/ld.so.preload",
		"/root/.ssh/", "/etc/pam.d/",
	} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// AssetContext scores based on the asset taxonomy class of the target.
// Reads `Input.AssetClass` (populated from ev.Tags["asset_class"] by
// the pipeline). Independent of path semantics — uses the canonical
// classification regardless of OS path conventions.
//
// Asset class weights (additive):
//
//	secret_file             → +5.0   /etc/shadow class
//	credential_store        → +4.0   ~/.aws/credentials class
//	session_store           → +4.0   broker outputs
//	workload_identity       → +4.0   kube service accounts
//	metadata_endpoint       → +5.0   IMDS
//	persistence_surface     → +3.0   cron/systemd/ld.so.preload
//	service_control         → +2.0   systemd ctl paths
//	package_state           → +1.5   /var/lib/dpkg, rpm
//	customer_data           → +3.0   DB storage paths
//	backup_data             → +3.0   /var/backups, /backup
//	code_root               → +1.0   /var/www, /srv, /opt
//	db_endpoint             → +1.5   mysql/postgres sockets
//	internal_socket         → +0.5
//	external_api_peer       → +1.0   uncategorized external
//	blob_storage            → +1.5   S3/GCS/Azure
//	webhook                 → +1.5   Slack/Discord hooks
//	git_hosting             → +1.0   GitHub/GitLab
//	identity_provider       → +0.5   OAuth providers
//	telemetry               → +0.5   Datadog/Sentry
//	config / log_sink / cache / temp → 0   benign or read-only
type AssetContext struct{}

func (AssetContext) Name() string { return "asset_context" }

func (AssetContext) Score(in Input) (float64, string) {
	if in.AssetClass == "" {
		return 0, ""
	}
	weights := map[string]float64{
		"secret_file":         5.0,
		"credential_store":    4.0,
		"session_store":       4.0,
		"workload_identity":   4.0,
		"metadata_endpoint":   5.0,
		"persistence_surface": 3.0,
		"service_control":     2.0,
		"package_state":       1.5,
		"customer_data":       3.0,
		"backup_data":         3.0,
		"code_root":           1.0,
		"db_endpoint":         1.5,
		"internal_socket":     0.5,
		"external_api_peer":   1.0,
		"blob_storage":        1.5,
		"webhook":             1.5,
		"git_hosting":         1.0,
		"identity_provider":   0.5,
		"telemetry":           0.5,
		"shared_cdn_edge":     0.5,
		// config / log_sink / cache / temp / unknown → 0
	}
	w, ok := weights[in.AssetClass]
	if !ok {
		return 0, ""
	}
	if w == 0 {
		return 0, ""
	}
	return w, "asset_class=" + in.AssetClass
}

// JITAttenuation reduces the score for events from a recognized userland
// JIT runtime (Node, JVM, Python, .NET, Ruby). These runtimes
// legitimately produce execution / file patterns that look like a shell
// exec from the kernel's perspective.
type JITAttenuation struct{}

func (JITAttenuation) Name() string { return "jit_attenuation" }

func (JITAttenuation) Score(in Input) (float64, string) {
	if in.JITAllowlisted {
		return -1.0, "actor in JIT runtime allowlist"
	}
	return 0, ""
}
