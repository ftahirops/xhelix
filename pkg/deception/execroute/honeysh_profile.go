package execroute

import (
	"strings"

	"github.com/xhelix/xhelix/pkg/prevent/apparmor"
)

// HoneyShProfile returns the standalone AppArmor profile for the
// xhelix-honeysh binary. Installed once per host (typically at
// /etc/apparmor.d/xhelix.honeysh). The per-service profile's "Px ->
// xhelix.honeysh" transition lands here.
//
// honey-sh is heavily sandboxed:
//   - Cannot exec anything except itself (we don't want attackers
//     pivoting out of honey-sh)
//   - Cannot read sensitive files OUTSIDE the fakes that responses.go
//     already serves from memory
//   - Cannot write anywhere except its log fd (passed by parent)
//   - No network — honey-sh talks only via stdin/stdout/log fd
//   - No capabilities
func HoneyShProfile() apparmor.Profile {
	var b strings.Builder
	b.WriteString("#include <tunables/global>\n\n")
	b.WriteString("# xhelix Protected Services — honey-sh deception profile.\n")
	b.WriteString("# Routed-to from per-service profiles via 'Px -> xhelix.honeysh'.\n")
	b.WriteString("# See PROTECTED_SERVICES_TRAP.md §4.1 + pkg/deception/execroute.\n\n")
	b.WriteString("profile xhelix.honeysh " + DefaultHoneyShPath + " {\n")
	b.WriteString("  #include <abstractions/base>\n\n")

	b.WriteString("  # Self only — attackers cannot pivot out of honey-sh\n")
	b.WriteString("  " + DefaultHoneyShPath + " mr,\n\n")

	b.WriteString("  # No network at all\n")
	b.WriteString("  deny network,\n\n")

	b.WriteString("  # No file writes except the inherited log fd (descriptors\n")
	b.WriteString("  # passed in from parent are exempt from AppArmor path checks)\n")
	b.WriteString("  deny /** w,\n\n")

	b.WriteString("  # Sensitive paths — honey-sh serves fakes from memory\n")
	b.WriteString("  # (responses.go), so no need to read these for real.\n")
	b.WriteString("  deny /etc/shadow r,\n")
	b.WriteString("  deny /etc/sudoers r,\n")
	b.WriteString("  deny /root/** r,\n")
	b.WriteString("  deny /home/*/.ssh/** r,\n")
	b.WriteString("  deny /home/*/.aws/** r,\n")
	b.WriteString("  deny /var/lib/xhelix/** r,\n\n")

	b.WriteString("  # No exec of any other binary — honey-sh is the leaf\n")
	b.WriteString("  deny /bin/** x,\n")
	b.WriteString("  deny /usr/bin/** x,\n")
	b.WriteString("  deny /sbin/** x,\n")
	b.WriteString("  deny /usr/sbin/** x,\n")
	b.WriteString("  deny /usr/local/bin/** x,\n\n")

	b.WriteString("  # No capabilities — strip everything\n")
	b.WriteString("  deny capability,\n\n")

	b.WriteString("  # No memory exploit primitives (defense in depth — honey-sh\n")
	b.WriteString("  # is pure-Go and never uses these, but block anyway)\n")
	b.WriteString("  deny /proc/*/mem rw,\n")
	b.WriteString("  deny /sys/kernel/security/** rw,\n")
	b.WriteString("  deny ptrace,\n")
	b.WriteString("  deny mount,\n")
	b.WriteString("}\n")

	return apparmor.Profile{
		Name: "xhelix.honeysh",
		Body: b.String(),
	}
}
