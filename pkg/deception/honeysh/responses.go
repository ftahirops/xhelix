package honeysh

import (
	"fmt"
	"regexp"
	"strings"
)

// respondTo dispatches one parsed command to its fake-output
// generator. Unknown commands → "command not found" (matching real
// bash semantics). Every response is plausible-but-fake and never
// touches the real filesystem.
//
// Design goal: an attacker running standard recon (`id`, `uname -a`,
// `ls /`, `cat /etc/passwd`, `ps`, `netstat`) gets believable output
// for 60+ seconds. The fakes are deliberately consistent — re-
// running `id` returns the same answer — so the attacker doesn't
// trip on contradictions.
func respondTo(cmd string, args []string, cfg *Config, cwd string) string {
	switch cmd {
	case "id":
		return fmt.Sprintf("uid=33(%s) gid=33(%s) groups=33(%s)\n",
			cfg.User, cfg.User, cfg.User)

	case "whoami":
		return cfg.User + "\n"

	case "hostname":
		return cfg.Host + "\n"

	case "pwd":
		return cwd + "\n"

	case "uname":
		return uname(args, cfg.Host)

	case "uptime":
		return " 14:23:12 up 47 days,  3:42,  0 users,  load average: 0.18, 0.21, 0.19\n"

	case "w", "who", "users", "last":
		// No interactive users — that's actually typical on a web host.
		return ""

	case "ls", "dir":
		return fakeLS(args, cwd)

	case "ll":
		// `ll` is usually `ls -alF` aliased
		return fakeLS(append([]string{"-l"}, args...), cwd)

	case "cat", "more", "less", "head", "tail":
		return fakeRead(args, cmd)

	case "echo":
		return strings.Join(args, " ") + "\n"

	case "env", "printenv":
		return fakeEnv(cfg)

	case "ps":
		return fakePS()

	case "netstat", "ss":
		return fakeNet(cmd, args)

	case "ifconfig":
		return fakeIfconfig()

	case "ip":
		return fakeIPCommand(args)

	case "df":
		return fakeDF()

	case "free":
		return fakeFree()

	case "history":
		// Empty history — looks like a fresh non-interactive session.
		return ""

	case "which", "type", "command":
		return fakeWhich(args)

	case "find":
		// Generic empty result — find is too varied to fake fully.
		return ""

	case "ping":
		if len(args) == 0 {
			return "ping: usage error: Destination address required\n"
		}
		return fmt.Sprintf("PING %s 56(84) bytes of data.\nFrom %s: Time to live exceeded\n", args[len(args)-1], cfg.Host)

	case "curl", "wget":
		// These should never reach here — Ring 1 blocks them. If
		// somehow they do, return a plausible network error.
		return fmt.Sprintf("%s: (7) Failed to connect: Connection refused\n", cmd)

	case "sudo":
		return cfg.User + " is not in the sudoers file. This incident will be reported.\n"

	case "su":
		return "su: Authentication failure\n"

	case "ssh":
		return "ssh: Could not resolve hostname: Temporary failure in name resolution\n"

	case "cd":
		// Handled in session.go before reaching here. Defensive.
		return ""

	case "":
		return ""
	}

	// Unknown — match bash exactly.
	return fmt.Sprintf("%s: command not found\n", cmd)
}

// --- per-command fakers ---

func uname(args []string, host string) string {
	full := func() string {
		// Mimic a recent Ubuntu LTS — most common deployment target.
		return fmt.Sprintf("Linux %s 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\n", host)
	}
	if len(args) == 0 {
		return "Linux\n"
	}
	for _, a := range args {
		switch a {
		case "-a", "--all":
			return full()
		case "-n", "--nodename":
			return host + "\n"
		case "-r", "--kernel-release":
			return "5.15.0-105-generic\n"
		case "-m", "--machine":
			return "x86_64\n"
		case "-s", "--kernel-name":
			return "Linux\n"
		case "-o", "--operating-system":
			return "GNU/Linux\n"
		}
	}
	return "Linux\n"
}

func fakeLS(args []string, cwd string) string {
	// Determine target dir (last non-flag arg, or cwd).
	target := cwd
	long := false
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "-l"), a == "--long":
			long = true
		case a == "-la", a == "-al":
			long = true
		case !strings.HasPrefix(a, "-"):
			target = a
		}
	}
	return lsFor(target, long)
}

// lsFor returns plausible content for the given path. Content is
// stable across calls so attacker doesn't see contradictions.
func lsFor(path string, long bool) string {
	entries, ok := fakeFSListing[path]
	if !ok {
		// Default: a few sensible files for unknown www-data subtree.
		entries = []entry{
			{name: "index.html", isDir: false, size: 4123},
			{name: "assets", isDir: true},
			{name: "robots.txt", isDir: false, size: 88},
		}
	}
	if !long {
		var sb strings.Builder
		for _, e := range entries {
			sb.WriteString(e.name)
			sb.WriteString("  ")
		}
		sb.WriteString("\n")
		return sb.String()
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "total %d\n", len(entries)*4)
	for _, e := range entries {
		mode := "-rw-r--r--"
		if e.isDir {
			mode = "drwxr-xr-x"
		}
		fmt.Fprintf(&sb, "%s 1 www-data www-data %6d Mar 15 09:42 %s\n", mode, e.size, e.name)
	}
	return sb.String()
}

type entry struct {
	name  string
	isDir bool
	size  int
}

// fakeFSListing is a small consistent fake filesystem snapshot.
var fakeFSListing = map[string][]entry{
	"/": {
		{name: "bin", isDir: true},
		{name: "boot", isDir: true},
		{name: "dev", isDir: true},
		{name: "etc", isDir: true},
		{name: "home", isDir: true},
		{name: "lib", isDir: true},
		{name: "lib64", isDir: true},
		{name: "media", isDir: true},
		{name: "mnt", isDir: true},
		{name: "opt", isDir: true},
		{name: "proc", isDir: true},
		{name: "root", isDir: true},
		{name: "run", isDir: true},
		{name: "sbin", isDir: true},
		{name: "srv", isDir: true},
		{name: "sys", isDir: true},
		{name: "tmp", isDir: true},
		{name: "usr", isDir: true},
		{name: "var", isDir: true},
	},
	"/var/www/html": {
		{name: "index.html", isDir: false, size: 4123},
		{name: "wp-admin", isDir: true},
		{name: "wp-content", isDir: true},
		{name: "wp-includes", isDir: true},
		{name: "wp-config.php", isDir: false, size: 5108},
		{name: "robots.txt", isDir: false, size: 88},
		{name: ".htaccess", isDir: false, size: 421},
	},
	"/home": {
		{name: "ubuntu", isDir: true},
	},
	"/tmp": {
		{name: ".X11-unix", isDir: true},
		{name: "systemd-private-abc123-nginx.service-xyz", isDir: true},
	},
}

// fakeRead returns plausible content for common sensitive files. The
// payloads are stable across calls and obviously fake on close
// inspection (random hashes, honey-only users).
func fakeRead(args []string, cmd string) string {
	if len(args) == 0 {
		return ""
	}
	// Strip flags; take last positional as file.
	var target string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			target = a
		}
	}
	if c, ok := fakeFileContent[target]; ok {
		return c
	}
	// File not in our fake set — match real `cat` for missing files.
	return fmt.Sprintf("%s: %s: No such file or directory\n", cmd, target)
}

// fakeFileContent — stable fake contents for files attackers love.
// /etc/shadow returns watermarked-but-realistic-looking hashes.
// /etc/passwd includes a honey-user "deploy".
var fakeFileContent = map[string]string{
	"/etc/passwd": `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
deploy:x:1001:1001:deploy:/home/deploy:/bin/bash
`,
	// Decoy shadow — random honey hashes that look crackable but
	// aren't real for anything. Marked with the "$y$" yescrypt prefix
	// to match modern distros.
	"/etc/shadow": `root:$y$j9T$qXc8WkVxJp4mLhT2yPwR3.$h5K4n7Bf2YqV0xRtMjN8sLgUcQpHvWzKbXyEfDoAtRm:19700:0:99999:7:::
daemon:*:19700:0:99999:7:::
bin:*:19700:0:99999:7:::
sys:*:19700:0:99999:7:::
www-data:*:19700:0:99999:7:::
ubuntu:$y$j9T$kP3mWqXrTbY2nLs9.HfV1.$8jKsRpQvWxNbZcDfGhYtUmJlOiPaQrXyVzKbHnSeFwI:19700:0:99999:7:::
deploy:$y$j9T$rNbXqYpKsWtMlZpV9.HjE2.$2pRsWvXqLmNbZkDfGhYtUcQrJlOhPaXyKbVzHnSeFwL:19700:0:99999:7:::
`,
	"/etc/hostname":  "webhost\n",
	"/etc/issue":     "Ubuntu 22.04.4 LTS \\n \\l\n\n",
	"/etc/os-release": `PRETTY_NAME="Ubuntu 22.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
`,
	"/proc/version": "Linux version 5.15.0-105-generic (buildd@lcy02-amd64-079) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0) #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024\n",
	"/proc/cpuinfo": "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) CPU @ 2.20GHz\ncpu MHz\t\t: 2200.000\ncache size\t: 56320 KB\n\n",
	"/etc/sudoers": `# This file MUST be edited with the 'visudo' command as root.
Defaults env_reset
Defaults mail_badpass
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

root    ALL=(ALL:ALL) ALL
deploy  ALL=(ALL:ALL) NOPASSWD: ALL
%admin  ALL=(ALL) ALL
%sudo   ALL=(ALL:ALL) ALL
`,
}

func fakeEnv(cfg *Config) string {
	return strings.Join([]string{
		"USER=" + cfg.User,
		"HOME=/var/www",
		"PWD=" + cfg.CWD,
		"SHELL=/bin/sh",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C.UTF-8",
		"HOSTNAME=" + cfg.Host,
	}, "\n") + "\n"
}

func fakePS() string {
	return "    PID TTY          TIME CMD\n" +
		"   1834 ?        00:00:00 nginx\n" +
		"   1835 ?        00:00:00 nginx\n" +
		"   1836 ?        00:00:00 nginx\n" +
		"   3421 ?        00:00:00 sh\n"
}

func fakeNet(cmd string, args []string) string {
	if cmd == "ss" {
		return "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n" +
			"tcp   LISTEN 0      511    0.0.0.0:80         0.0.0.0:*\n" +
			"tcp   LISTEN 0      511    0.0.0.0:443        0.0.0.0:*\n"
	}
	return "Active Internet connections (servers and established)\n" +
		"Proto Recv-Q Send-Q Local Address      Foreign Address    State\n" +
		"tcp        0      0 0.0.0.0:80         0.0.0.0:*          LISTEN\n" +
		"tcp        0      0 0.0.0.0:443        0.0.0.0:*          LISTEN\n"
}

func fakeIfconfig() string {
	return `eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.42  netmask 255.255.255.0  broadcast 10.0.0.255
        ether 02:11:33:55:77:99  txqueuelen 1000  (Ethernet)
        RX packets 42384281  bytes 9128492311
        TX packets 38291248  bytes 4982149811

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
`
}

func fakeIPCommand(args []string) string {
	if len(args) == 0 {
		return "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n"
	}
	switch args[0] {
	case "a", "addr", "address":
		return fakeIfconfig()
	case "r", "route":
		return "default via 10.0.0.1 dev eth0\n10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.42\n"
	}
	return ""
}

func fakeDF() string {
	return "Filesystem      1K-blocks     Used Available Use% Mounted on\n" +
		"/dev/sda1        51474044 21384921  27513411  44% /\n" +
		"tmpfs             2027184        0   2027184   0% /dev/shm\n"
}

func fakeFree() string {
	return "              total        used        free      shared  buff/cache   available\n" +
		"Mem:        4054368     1438216      943020       28804     1673132     2329441\n" +
		"Swap:             0           0           0\n"
}

func fakeWhich(args []string) string {
	if len(args) == 0 {
		return ""
	}
	// Lie: claim every common binary is at /usr/bin/<name> to keep
	// the attacker on a fruitful trail.
	known := map[string]string{
		"ls":     "/usr/bin/ls",
		"cat":    "/usr/bin/cat",
		"ps":     "/usr/bin/ps",
		"id":     "/usr/bin/id",
		"echo":   "/usr/bin/echo",
		"which":  "/usr/bin/which",
		"sh":     "/bin/sh",
		"bash":   "/bin/bash",
		"curl":   "/usr/bin/curl",
		"wget":   "/usr/bin/wget",
		"python": "/usr/bin/python3",
		"python3": "/usr/bin/python3",
		"perl":   "/usr/bin/perl",
		"nc":     "/usr/bin/nc",
	}
	if p, ok := known[args[0]]; ok {
		return p + "\n"
	}
	return ""
}

// extractIOCs harvests indicators from the raw command line into
// the CommandEvent. Cheap regex scan — comprehensive analysis is
// the IOC-extraction pipeline's job (P-PS.11).
var (
	reURL    = regexp.MustCompile(`https?://[^\s'"]+`)
	reIPv4   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reDomain = regexp.MustCompile(`\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b`)
)

func extractIOCs(line string, ev *CommandEvent) {
	ev.URLs = uniq(reURL.FindAllString(line, -1))
	ev.IPs = uniq(reIPv4.FindAllString(line, -1))
	// Domains heuristic — exclude bare IPs and our fake hosts.
	domains := reDomain.FindAllString(line, -1)
	var keep []string
	for _, d := range domains {
		if reIPv4.MatchString(d) {
			continue
		}
		// Filter common "fragments" that look like domains but aren't
		// (e.g. "ls.so", "lib.so.6").
		if strings.HasSuffix(d, ".so") || strings.HasSuffix(d, ".conf") ||
			strings.HasSuffix(d, ".txt") || strings.HasSuffix(d, ".html") {
			continue
		}
		keep = append(keep, d)
	}
	ev.Domains = uniq(keep)
}

func uniq(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
