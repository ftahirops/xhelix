package lineagescore

// SensitivityBoost scales a signal's base evidence weight by what the
// event touched, using tags the pipeline already stamps
// (pkg/assetclass -> "asset_class", pkg/secrettaint -> "secret_taint").
//
// Multiplier from secret_taint state (read of / egress from a tainted
// lineage is the strongest local signal):
//
//	secret_touched, outbound_restricted -> x2
//	containment_required                -> x3
//	clean / unknown / absent            -> x1
//
// Then a sensitive asset_class adds a flat +40 (applied after the
// multiplier). Result is capped at maxSignalWeight so one signal can't
// exceed a single critical verdict alone — a chain still needs
// corroboration. See docs/RULE_CATEGORIES.md.
func SensitivityBoost(base int, tags map[string]string) int {
	w := base
	if tags != nil {
		switch tags["secret_taint"] {
		case "secret_touched", "outbound_restricted":
			w *= 2
		case "containment_required":
			w *= 3
		}
		if isSensitiveClass(tags["asset_class"]) {
			w += 40
		}
	}
	if w > maxSignalWeight {
		w = maxSignalWeight
	}
	return w
}

const maxSignalWeight = 200

// isSensitiveClass lists the exact assetclass.Class string values that
// assetclass.Class.IsSensitive() returns true for. Kept local so this
// package has no import dependency on assetclass (keeps the engine pure
// and avoids cycles). A drift-guard test (weight_assetclass_test.go)
// fails loudly if assetclass and this list disagree.
func isSensitiveClass(c string) bool {
	switch c {
	case "secret_file", "credential_store", "session_store",
		"workload_identity", "metadata_endpoint", "service_control",
		"persistence_surface", "customer_data", "backup_data":
		return true
	}
	return false
}

// Tier maps a verdict score to a human tier for the synthesized alert.
func Tier(score int) string {
	switch {
	case score >= 120:
		return "critical"
	case score >= 80:
		return "high"
	case score >= 40:
		return "watch"
	default:
		return "none"
	}
}
