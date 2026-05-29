// Package egressledger is a 3-tier hybrid store for outbound network flows.
//
// Tier 1 (HOT) is an in-memory ring covering the last HotWindow (default 60m)
// at 1-minute bucket granularity. Tier 2 (WARM) is a badger LSM keyed by
// big-endian bucket timestamp at 5-minute granularity, retained for 48h with
// zstd compression. Tier 3 (COLD) is per-day parquet files at 1-hour bucket
// granularity, retained for RetentionDays (default 14) with zstd column
// compression.
//
// The Observe path is lock-cheap and non-blocking. Tick is expected to be
// driven by the daemon every minute and performs hot->warm slide, periodic
// warm->cold roll-up, and cold pruning. Public Query* methods auto-pick a
// tier based on the requested time range.
//
// All storage lives under Options.Dir (typically /var/lib/xhelix/egressledger).
// The package is CGO-free: badger v4 (pure Go) and parquet-go/parquet-go.
package egressledger
