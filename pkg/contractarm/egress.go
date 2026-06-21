package contractarm

import "strings"

// EgressDirectives renders the systemd [Service] egress block for a
// deny-by-default policy. `localhost` and `link-local` are ALWAYS allowed
// (loopback 127.0.0.0/8 + ::1, and 169.254.0.0/16 + fe80::/64) so a
// lockdown never severs loopback or internal autoconfiguration. The caller
// passes the operator-declared allow CIDRs; blank entries are dropped.
// `IPAddressDeny=any` is the default-deny floor — systemd lets an explicit
// IPAddressAllow entry win over it. Returns the two directive lines with no
// trailing newline; the empty allow-set still yields a valid lockdown.
func EgressDirectives(allowCIDRs []string) string {
	allow := []string{"localhost", "link-local"}
	for _, c := range allowCIDRs {
		if c = strings.TrimSpace(c); c != "" {
			allow = append(allow, c)
		}
	}
	return "IPAddressAllow=" + strings.Join(allow, " ") + "\nIPAddressDeny=any"
}
