package assetclass

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// operatorRule is the YAML shape for /etc/xhelix/assetclass.d/*.yaml.
//
// Example operator config:
//
//	rules:
//	  - path_prefix: /opt/myapp/data/
//	    class: customer_data
//	    applies_to_roles:
//	      - myapp-worker
//	  - path_prefix: /mnt/backups/
//	    class: backup_data
type operatorRule struct {
	PathPrefix     string   `yaml:"path_prefix"`
	Class          string   `yaml:"class"`
	AppliesToRoles []string `yaml:"applies_to_roles,omitempty"`
}

type operatorFile struct {
	Rules []operatorRule `yaml:"rules"`
}

// LoadOperatorRules reads every *.yaml file under dir and returns a
// validated rule set. Missing dir is not an error (returns empty).
//
// Validation:
//   - PathPrefix must be a non-empty absolute path
//   - Class must be a known asset class string
//   - Operator cannot DECLARE a SENSITIVE class via override (sensitive
//     classes must come from the static rule table — otherwise an
//     operator could mark a benign path as `secret_file` and trick the
//     verifier into over-blocking). Sensitive classes via override are
//     REJECTED with a warning logged.
//
// Returns ([]pathRule, []error). Both may be non-empty (good rules from
// one file + errors from another).
func LoadOperatorRules(dir string) ([]pathRule, []error) {
	var rules []pathRule
	var errs []error

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []error{fmt.Errorf("read %s: %w", dir, err)}
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasSuffix(n, ".yaml") && !strings.HasSuffix(n, ".yml") {
			continue
		}
		path := filepath.Join(dir, n)
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			errs = append(errs, fmt.Errorf("%s: read: %w", n, rerr))
			continue
		}
		var f operatorFile
		if err := yaml.Unmarshal(data, &f); err != nil {
			errs = append(errs, fmt.Errorf("%s: yaml: %w", n, err))
			continue
		}
		for i, r := range f.Rules {
			if r.PathPrefix == "" {
				errs = append(errs, fmt.Errorf("%s rule[%d]: path_prefix required", n, i))
				continue
			}
			if !strings.HasPrefix(r.PathPrefix, "/") {
				errs = append(errs, fmt.Errorf("%s rule[%d]: path_prefix must be absolute, got %q", n, i, r.PathPrefix))
				continue
			}
			class, ok := parseClass(r.Class)
			if !ok {
				errs = append(errs, fmt.Errorf("%s rule[%d]: unknown class %q", n, i, r.Class))
				continue
			}
			// Reject operator-declared SENSITIVE classes — those must
			// come from the static table to preserve the protect-our-own
			// guarantee.
			if class.IsSensitive() {
				errs = append(errs, fmt.Errorf(
					"%s rule[%d]: operator cannot declare sensitive class %q via override; sensitive classes come from the static rule table only",
					n, i, r.Class))
				continue
			}
			rules = append(rules, pathRule{
				PathPrefix:     r.PathPrefix,
				Class:          class,
				AppliesToRoles: r.AppliesToRoles,
			})
		}
	}

	return rules, errs
}

// parseClass maps a YAML class string back to the typed Class.
func parseClass(s string) (Class, bool) {
	known := map[string]Class{
		string(AssetConfig):           AssetConfig,
		string(AssetLogSink):          AssetLogSink,
		string(AssetCache):            AssetCache,
		string(AssetTemp):             AssetTemp,
		string(AssetSecretFile):       AssetSecretFile,
		string(AssetCredentialStore):  AssetCredentialStore,
		string(AssetSessionStore):     AssetSessionStore,
		string(AssetWorkloadIdentity): AssetWorkloadIdentity,
		string(AssetMetadataEndpoint): AssetMetadataEndpoint,
		string(AssetPackageState):     AssetPackageState,
		string(AssetServiceControl):   AssetServiceControl,
		string(AssetPersistence):      AssetPersistence,
		string(AssetCodeRoot):         AssetCodeRoot,
		string(AssetCustomerData):     AssetCustomerData,
		string(AssetBackupData):       AssetBackupData,
		string(AssetInternalSocket):   AssetInternalSocket,
		string(AssetDBEndpoint):       AssetDBEndpoint,
		string(AssetBlobStorage):      AssetBlobStorage,
		string(AssetWebhook):          AssetWebhook,
		string(AssetMessagingPlatform): AssetMessagingPlatform,
		string(AssetGitHosting):       AssetGitHosting,
		string(AssetIdentityProvider): AssetIdentityProvider,
		string(AssetTelemetry):        AssetTelemetry,
		string(AssetExternalAPI):      AssetExternalAPI,
	}
	c, ok := known[s]
	return c, ok
}
