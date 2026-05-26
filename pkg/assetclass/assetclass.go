// Package assetclass provides a stable taxonomy for classifying file
// paths, unix sockets, and network destinations into "asset classes" —
// semantic categories the verifier and incident scorer use to weight
// behavior independent of raw path strings.
//
// The taxonomy is intentionally narrow (24 classes). Each class has a
// well-defined operational meaning so the verifier's asset-context
// domain and the incidentgraph's evidence scoring can apply consistent
// weights without re-parsing paths.
//
// Phase B.1 of the BRP implementation plan
// (docs/BRP_IMPLEMENTATION_PLAN_2026-05-24.md). Build spec contract at
// docs/BRP_CORRELATION_BUILD_SPEC_2026-05-24.md §3.2.
package assetclass

// Class is the stable asset classification.
//
// Values are intentionally short string tokens so they can be stamped
// directly on event tags (asset_class=<value>) and round-trip cleanly
// through JSON / logs without escaping.
type Class string

const (
	// ClassUnknown is the zero value — used when no rule matched and
	// no operator override applies. Distinct from any specific class so
	// callers can detect classification failure.
	ClassUnknown Class = ""

	AssetConfig           Class = "config"
	AssetLogSink          Class = "log_sink"
	AssetCache            Class = "cache"
	AssetTemp             Class = "temp"
	AssetSecretFile       Class = "secret_file"
	AssetCredentialStore  Class = "credential_store"
	AssetSessionStore     Class = "session_store"
	AssetWorkloadIdentity Class = "workload_identity"
	AssetMetadataEndpoint Class = "metadata_endpoint"
	AssetPackageState     Class = "package_state"
	AssetServiceControl   Class = "service_control"
	AssetPersistence      Class = "persistence_surface"
	AssetCodeRoot         Class = "code_root"
	AssetCustomerData     Class = "customer_data"
	AssetBackupData       Class = "backup_data"
	AssetInternalSocket   Class = "internal_socket"
	AssetDBEndpoint       Class = "db_endpoint"
	AssetBlobStorage      Class = "blob_storage"
	AssetWebhook          Class = "webhook"
	AssetGitHosting       Class = "git_hosting"
	AssetIdentityProvider Class = "identity_provider"
	AssetTelemetry        Class = "telemetry"
	// AssetExternalAPI is the catch-all when no more specific class
	// can be resolved. Resolvers MUST prefer specific classes
	// (BlobStorage, Webhook, GitHosting, IdentityProvider, Telemetry)
	// when destination metadata supports it. Audit usage periodically;
	// high proportion of events landing here indicates resolver gaps.
	AssetExternalAPI Class = "external_api_peer"
)

// IsSensitive returns true when the class represents content that
// disclosure of, or write to, materially changes host trust posture.
// Used as a quick gate by callers before running fuller verifier scoring.
func (c Class) IsSensitive() bool {
	switch c {
	case AssetSecretFile, AssetCredentialStore, AssetSessionStore,
		AssetWorkloadIdentity, AssetMetadataEndpoint,
		AssetServiceControl, AssetPersistence, AssetCustomerData,
		AssetBackupData:
		return true
	}
	return false
}

// Resolver classifies paths, sockets, and hosts into stable asset classes.
//
// Implementations should be safe for concurrent use; the resolver is
// hit on every BRP-evaluated event.
//
// All three methods accept a role string when one is available. Same
// path/host can resolve to different classes depending on the actor's
// role — e.g. /var/log/nginx/access.log is `log_sink` for nginx but
// `customer_data` for a backup daemon. role="" means "no role context",
// in which case the resolver uses the most-conservative classification.
type Resolver interface {
	ClassifyPath(path, role string) Class
	ClassifySocket(socketPath string) Class
	ClassifyHost(ip, sni string, port uint16) Class
}
