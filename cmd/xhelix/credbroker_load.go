package main

import (
	"context"
	"log/slog"

	"github.com/xhelix/xhelix/pkg/credbroker"
)

// loadCredBroker constructs the daemon's credbroker.Broker.
// Reads the master key from /var/lib/xhelix/credbroker.key (creates
// it if missing) and the policy contract from
// /etc/xhelix/credbroker.yaml (falls back to DefaultContract).
func loadCredBroker(log *slog.Logger) *credbroker.Broker {
	key, err := credbroker.LoadOrCreateMasterKey("/var/lib/xhelix/credbroker.key")
	if err != nil {
		log.Warn("credbroker master key load failed (using empty key — broker will refuse all)",
			"err", err)
		// Return an unusable broker so the daemon doesn't crash but
		// every Decide() denies. Better than silent allow.
		// 32-byte zero is technically a valid key but operator will
		// see immediate failures.
		zero := make([]byte, 32)
		s, _ := credbroker.NewAESGCMSealer(zero, "FAILED-default")
		return credbroker.NewBroker(s, 0)
	}
	sealer, err := credbroker.NewAESGCMSealer(key, "default")
	if err != nil {
		log.Warn("credbroker sealer init failed", "err", err)
		zero := make([]byte, 32)
		s, _ := credbroker.NewAESGCMSealer(zero, "FAILED-default")
		return credbroker.NewBroker(s, 0)
	}

	b := credbroker.NewBroker(sealer, 0)

	contract, err := credbroker.LoadContract("/etc/xhelix/credbroker.yaml")
	if err != nil {
		log.Warn("credbroker contract load failed (using default contract)",
			"err", err)
		contract = credbroker.DefaultContract()
	} else if contract == nil || len(contract.Rules) == 0 {
		contract = credbroker.DefaultContract()
		log.Info("credbroker using built-in default contract")
	} else {
		log.Info("credbroker contract loaded",
			"path", "/etc/xhelix/credbroker.yaml",
			"rules", len(contract.Rules),
			"default_deny", contract.DefaultDeny)
	}
	b.WithContract(contract)

	// Layer-2 contracts: /etc/xhelix/contracts.d/*.yaml. Each file is
	// a per-app declared access policy (binary + allowed sealed
	// paths + optional SHA pin + parent shape + rate cap). Missing
	// dir is silently OK. Per-file parse errors are logged loudly
	// but don't block boot.
	appSet, errs := credbroker.LoadAppContractsDir("/etc/xhelix/contracts.d")
	for _, e := range errs {
		log.Warn("credbroker app-contract load error", "err", e)
	}
	if n := len(appSet.Contracts()); n > 0 {
		log.Info("credbroker Layer-2 app contracts loaded", "count", n)
	}
	b.WithAppContracts(appSet)

	return b
}

// startFanGate brings up the fanotify-based file_open interception
// gate on Linux. Walks /var/lib/xhelix/sealed/ (and any operator-
// configured roots) to find .sealed files and FAN_MARK them with
// FAN_OPEN_PERM. From that point on every open(2) of a sealed file
// suspends until the broker's Decide returns. Honey decoys (.honey)
// are also marked and every open emits a high-confidence alert.
//
// emit (may be nil) is the daemon's alert publisher. When non-nil
// the fangate routes every deny / honey-touch into model.Alert so
// the rule engine, sinks, and pkg/takeover scorer all observe it.
//
// Failure modes (all logged + degrade gracefully — the rest of
// xhelix keeps working):
//   - missing CAP_SYS_ADMIN: FanotifyInit returns EPERM
//   - non-Linux: returns "linux only" error
//   - no .sealed files present yet: count=0 (operator seals
//     credentials later via `xhelixctl credbroker seal`)
func startFanGate(ctx context.Context, log *slog.Logger, broker *credbroker.Broker, emit func(a interface{})) {
	gate, err := credbroker.NewFanGate(broker, log)
	if err != nil {
		log.Warn("credbroker fangate disabled (init failed)", "err", err)
		return
	}
	if emit != nil {
		em := &credBrokerAlertEmitter{emit: castEmit(emit)}
		gate.WithAlertEmitter(em)
	}
	sealRoots := []string{
		"/var/lib/xhelix/sealed",
		"/root/.aws", "/root/.gcp", "/root/.kube", "/root/.docker",
		"/root/.config/gh", "/root/.config/gcloud", "/root/.config/op",
		"/etc/xhelix/sealed",
	}
	totalSealed := 0
	totalHoney := 0
	for _, root := range sealRoots {
		n, _ := gate.MarkSealedFilesIn(root)
		totalSealed += n
		h, _ := gate.MarkHoneyFilesIn(root)
		totalHoney += h
	}
	if err := gate.Start(ctx); err != nil {
		log.Warn("credbroker fangate start failed", "err", err)
		return
	}
	log.Info("credbroker fangate started",
		"sealed_files_marked", totalSealed,
		"honey_files_marked", totalHoney,
		"seal_roots", sealRoots)
}

