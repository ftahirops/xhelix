package incidentgraph

// intent.go — TTP tag mapping, MITRE technique IDs, and intent
// classification rules.

// ttpForRule maps a rule_id string to a short TTP tag suitable for
// operator dashboards. The mapping is intentionally narrow — only
// rules that have a clear TTP semantic are mapped; the rest produce
// "" (which the engine treats as "no TTP from this rule, no tag added").
//
// New rules added in Phases A-D get entries here so the incidentgraph
// can classify them. Unmapped rule_ids show up in the FEATURE_CATALOG
// review as candidates.
func ttpForRule(ruleID string) string {
	switch ruleID {
	// L0 invariants + role violations
	case "brp.hard_deny":
		return "policy_violation"
	case "brp.verify_protected_path":
		return "protected_path_touch"

	// Reverse shells / web → shell
	case "revshell.detected":
		return "reverse_shell"
	case "shell_with_socket_fd":
		return "shell_with_socket"
	case "web_spawns_shell":
		return "web_role_shell_spawn"

	// Memory-implant patterns
	case "memfd_run_pattern":
		return "memfd_execution"
	case "mem_mprotect_rwx":
		return "rwx_memory_alloc"
	case "process_injection_ptrace":
		return "process_injection"

	// Persistence
	case "ssh_key_added_root":
		return "authorized_keys_modified"
	case "cron_new_unit":
		return "cron_persistence"
	case "ld_preload_drift":
		return "ld_preload_drift"
	case "pam_module_modified":
		return "pam_hijack"

	// Egress / C2
	case "beacon.detected":
		return "c2_beacon"
	case "dns_exfil.detected":
		return "dns_exfil"
	case "metadata.access_by_unexpected", "metadata_svc_unexpected":
		return "metadata_access"
	case "egressguard.shadow_deny", "egressguard.deny":
		return "egress_policy_violation"

	// Capability / privilege
	case "cap.gained":
		return "capability_gain"
	case "contescape.detected":
		return "container_escape"

	// File-system / persistence-surface writes
	case "fim.drift":
		return "file_integrity_drift"

	// Discovery / LOLBin
	case "lolbin.suspicious":
		return "lolbin_use"
	case "bpf_syscall_unexpected":
		return "bpf_syscall_misuse"

	// Tmp / SUID
	case "binary_runs_from_tmp":
		return "tmpfs_execution"
	case "suid_drift":
		return "suid_drift"
	}
	return ""
}

// mitreForRule maps a rule_id to a MITRE ATT&CK technique ID. The
// mapping is intentionally conservative — only rules with an
// unambiguous technique match get an ID. Rules can map to multiple
// techniques; we list only the most-specific.
func mitreForRule(ruleID string) string {
	switch ruleID {
	// Initial access / valid accounts
	case "ssh_key_added_root":
		return "T1098" // Account Manipulation
	case "metadata.access_by_unexpected", "metadata_svc_unexpected":
		return "T1552.005" // Unsecured Credentials: Cloud Instance Metadata API

	// Execution
	case "shell_with_socket_fd", "revshell.detected":
		return "T1059.004" // Command and Scripting Interpreter: Unix Shell
	case "memfd_run_pattern":
		return "T1620" // Reflective Code Loading

	// Persistence
	case "cron_new_unit":
		return "T1053.003" // Scheduled Task/Job: Cron
	case "pam_module_modified":
		return "T1556.003" // Modify Authentication Process: Pluggable Authentication Modules
	case "ld_preload_drift":
		return "T1574.006" // Hijack Execution Flow: Dynamic Linker Hijacking

	// Privilege Escalation
	case "cap.gained":
		return "T1068" // Exploitation for Privilege Escalation
	case "process_injection_ptrace":
		return "T1055.008" // Process Injection: Ptrace System Calls

	// Defense Evasion
	case "fim.drift":
		return "T1070.004" // Indicator Removal: File Deletion (broad mapping)
	case "binary_runs_from_tmp":
		return "T1564.001" // Hide Artifacts: Hidden Files and Directories

	// Credential Access
	case "brp.hard_deny", "brp.verify_protected_path":
		// Generic — actual MITRE depends on context. Leave unmapped.
		return ""

	// Discovery
	case "bpf_syscall_unexpected":
		return "T1620" // Reflective Code Loading (BPF abuse)

	// Lateral movement
	case "contescape.detected":
		return "T1611" // Escape to Host

	// Command and Control
	case "beacon.detected":
		return "T1071" // Application Layer Protocol
	case "dns_exfil.detected":
		return "T1071.004" // Application Layer Protocol: DNS

	// Exfiltration
	case "egressguard.deny", "egressguard.shadow_deny":
		return "T1041" // Exfiltration Over C2 Channel (broad)
	}
	return ""
}

// classifyIntent picks an IntentCategory from accumulated TTP tags +
// MITRE IDs. Multi-category incidents pick the highest-impact category
// per the priority order:
//
//   impact > theft > c2 > privilege > lateral > persistence > unknown
//
// This is rule-based (not ML) — the operator should be able to read
// the TTP tags and predict the intent label.
func classifyIntent(ttps []string, mitre []string) IntentCategory {
	has := map[string]bool{}
	for _, t := range ttps {
		has[t] = true
	}
	for _, m := range mitre {
		has[m] = true
	}

	// Impact (highest priority — overrides all)
	if has["destructive_write"] || has["mass_rename"] || has["backup_destroy"] {
		return IntentImpact
	}

	// Theft signals
	if (has["metadata_access"] || has["protected_path_touch"]) &&
		(has["egress_policy_violation"] || has["c2_beacon"] || has["dns_exfil"]) {
		return IntentTheft
	}

	// C2 signals
	if has["c2_beacon"] || has["dns_exfil"] || has["egress_policy_violation"] {
		return IntentC2
	}

	// Privilege escalation
	if has["capability_gain"] || has["process_injection"] ||
		has["container_escape"] || has["T1068"] {
		return IntentPrivilege
	}

	// Lateral movement
	if has["authorized_keys_modified"] || has["T1021"] {
		return IntentLateral
	}

	// Persistence
	if has["cron_persistence"] || has["pam_hijack"] || has["ld_preload_drift"] ||
		has["file_integrity_drift"] {
		return IntentPersistence
	}

	// Default
	return IntentUnknown
}
