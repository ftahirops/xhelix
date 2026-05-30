package lineagescore

import (
	"testing"

	"github.com/xhelix/xhelix/pkg/assetclass"
)

// TestSensitiveClassSet_MatchesAssetclass guards against drift between
// isSensitiveClass (string form, local) and assetclass.Class.IsSensitive
// (the source of truth). If assetclass changes its sensitive set, this
// fails so someone updates isSensitiveClass.
func TestSensitiveClassSet_MatchesAssetclass(t *testing.T) {
	// The exact sensitive class string values per assetclass.IsSensitive.
	sensitive := []string{
		"secret_file", "credential_store", "session_store",
		"workload_identity", "metadata_endpoint", "service_control",
		"persistence_surface", "customer_data", "backup_data",
	}
	// Every value we treat as sensitive must agree with assetclass.
	for _, c := range sensitive {
		if !assetclass.Class(c).IsSensitive() {
			t.Errorf("isSensitiveClass lists %q but assetclass.IsSensitive=false — reconcile", c)
		}
		if !isSensitiveClass(c) {
			t.Errorf("assetclass-sensitive %q not in isSensitiveClass — reconcile", c)
		}
	}
	// And a few non-sensitive classes must NOT be sensitive in either.
	for _, c := range []string{"config", "log_sink", "cache", "temp", "code_root", "db_endpoint", "telemetry"} {
		if assetclass.Class(c).IsSensitive() {
			t.Errorf("assetclass now treats %q as sensitive — add it to isSensitiveClass + sensitive list", c)
		}
		if isSensitiveClass(c) {
			t.Errorf("isSensitiveClass wrongly treats %q as sensitive", c)
		}
	}
}
