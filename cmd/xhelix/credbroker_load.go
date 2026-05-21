package main

import (
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
	return b
}
