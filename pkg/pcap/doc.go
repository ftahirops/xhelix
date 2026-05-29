// Package pcap manages on-demand tcpdump captures for the operator.
//
// All captures are bounded by size + duration; there is no continuous
// capture. Captures land under <dir>/<id>.pcap (typically
// /var/lib/xhelix/captures/) and are served via the web layer at
// /api/egress/capture/<id>/download.
//
// Capture filters are validated against a strict allowlist before
// being passed to tcpdump — only [a-zA-Z0-9 .:/_-] are accepted to
// prevent shell injection or argument smuggling. Filters that look
// like BPF (host X, port Y, etc.) pass through; anything with shell
// metacharacters is rejected.
//
// Hard caps:
//   - max 5 concurrent captures
//   - max 500 MB per capture
//   - max 30 minutes per capture
//   - files older than 24h are pruned by Tick()
//
// tcpdump must be installed at /usr/sbin/tcpdump or /usr/bin/tcpdump.
// If absent, NewManager returns an error and the daemon should log
// the gap; the UI then surfaces an "unavailable" placeholder.
package pcap
