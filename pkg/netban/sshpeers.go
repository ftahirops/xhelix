package netban

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

// activeSSHPeers returns the unique set of remote IPs that have an
// established TCP connection to local port 22 right now. Reads
// /proc/net/tcp and /proc/net/tcp6.
//
// Used by EngageQuarantine as a "are we about to lock out the
// operator?" safety check. Best-effort: if /proc/net/tcp can't be
// read for any reason, returns an empty list and EngageQuarantine
// will not block on the missing data (the caller's overall logic
// stays sound — the operator simply gets the empty-allow-list refusal
// path or the explicit override).
func activeSSHPeers() ([]string, error) {
	out := map[string]struct{}{}
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		ips, err := scanProcNetTCP(p, 22)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			out[ip] = struct{}{}
		}
	}
	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	return keys, nil
}

// scanProcNetTCP returns remote-peer IPs of established connections
// where local-port == localPort. Format spec for /proc/net/tcp:
// columns local_address rem_address st (1, 2, 3 0-indexed in fields[1:]).
// "01" in the st column means TCP_ESTABLISHED.
func scanProcNetTCP(path string, localPort uint16) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		local := f[1]
		remote := f[2]
		state := f[3]
		if state != "01" { // not ESTABLISHED
			continue
		}
		_, lport := splitProcAddr(local)
		if lport != localPort {
			continue
		}
		raddr, _ := splitProcAddr(remote)
		if raddr == nil {
			continue
		}
		out = append(out, raddr.String())
	}
	return out, sc.Err()
}

// splitProcAddr parses an address like "0100007F:0016" (v4) or
// "00000000000000000000000001000000:0016" (v6) into (net.IP, port).
// Hex bytes are little-endian-grouped per /proc/net/tcp's quirky
// representation; the 32-bit grouping in v6 needs reversal too.
func splitProcAddr(s string) (net.IP, uint16) {
	colon := strings.IndexByte(s, ':')
	if colon < 0 {
		return nil, 0
	}
	addrHex := s[:colon]
	portHex := s[colon+1:]

	raw, err := hex.DecodeString(addrHex)
	if err != nil {
		return nil, 0
	}
	// Reverse bytes within each 4-byte group (kernel writes le u32).
	for i := 0; i+4 <= len(raw); i += 4 {
		raw[i], raw[i+3] = raw[i+3], raw[i]
		raw[i+1], raw[i+2] = raw[i+2], raw[i+1]
	}
	var ip net.IP
	switch len(raw) {
	case 4:
		ip = net.IP(raw)
	case 16:
		ip = net.IP(raw)
	default:
		return nil, 0
	}

	var port uint16
	if _, err := fmt.Sscanf(portHex, "%X", &port); err != nil {
		return nil, 0
	}
	return ip, port
}
