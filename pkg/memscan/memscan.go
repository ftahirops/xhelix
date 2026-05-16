// Package memscan scans a running process's memory for indicator
// patterns.
//
// This is YARA-lite, not YARA. CGO YARA bindings would break the
// static-binary promise; instead we implement what 80% of in-house
// detection rules actually use: byte-string match (with ASCII or hex
// encoding) and Go regex over readable regions. Anchored patterns and
// distance/order constraints between patterns are intentionally not
// supported — those belong in a real YARA process if you need them.
//
// The scanner reads /proc/<pid>/maps to find readable, non-special
// regions, then opens /proc/<pid>/mem and pread64()s each region.
// Heap (rw-p [heap]), stack ([stack]), and anonymous rw-p mappings
// are scanned by default; file-backed r-xp regions are skipped because
// they are the on-disk binary already (use FIM or YARA-on-disk for
// those). Override via Options if you need the full address space.
//
// Requires CAP_SYS_PTRACE or equivalent (e.g., root) on most kernels.
package memscan

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Pattern is one detection rule.
type Pattern struct {
	Name     string
	Severity string // "info" | "notice" | "warning" | "critical"
	// Exactly one of the following must be set.
	Bytes  []byte         // raw byte match
	Regex  *regexp.Regexp // applied as []byte
	// Description is shown verbatim in match output.
	Description string
}

// Match is one hit.
type Match struct {
	PatternName string
	Severity    string
	Description string
	Address     uint64 // virtual address in target process
	Region      string // e.g., "[heap]", "[stack]", "anon-rw"
	Excerpt     string // up to 64 bytes around the hit, hex-encoded
}

// Options tune the scanner.
type Options struct {
	// IncludeExecutable, when true, also scans r-xp regions. Default
	// false because those are the on-disk binary. Useful for catching
	// in-memory shellcode patched into PROT_EXEC pages.
	IncludeExecutable bool
	// MaxRegionBytes caps a single region's read. 0 = unlimited.
	MaxRegionBytes int64
	// MaxMatchesPerPattern stops searching a region after N hits.
	MaxMatchesPerPattern int
}

// Scan opens /proc/pid and runs every pattern across every readable
// region. Returns all matches; an empty slice means clean.
func Scan(pid int, patterns []Pattern, opts Options) ([]Match, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("memscan: invalid pid %d", pid)
	}
	for _, p := range patterns {
		if p.Bytes == nil && p.Regex == nil {
			return nil, fmt.Errorf("memscan: pattern %q has neither Bytes nor Regex", p.Name)
		}
	}
	if opts.MaxMatchesPerPattern == 0 {
		opts.MaxMatchesPerPattern = 16
	}

	regions, err := readMaps(pid)
	if err != nil {
		return nil, err
	}

	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return nil, err
	}
	defer mem.Close()

	var hits []Match
	for _, r := range regions {
		if !r.Readable {
			continue
		}
		if r.Executable && !opts.IncludeExecutable {
			continue
		}
		if r.Special && !(r.Tag == "[heap]" || r.Tag == "[stack]") {
			continue
		}

		size := int64(r.End - r.Start)
		if opts.MaxRegionBytes > 0 && size > opts.MaxRegionBytes {
			size = opts.MaxRegionBytes
		}
		if size <= 0 || size > 1<<31 {
			continue
		}
		buf := make([]byte, size)
		n, err := mem.ReadAt(buf, int64(r.Start))
		if err != nil && err != io.EOF {
			// EIO on unmapped pages is normal; just skip.
			continue
		}
		buf = buf[:n]

		for _, p := range patterns {
			matchesInRegion := 0
			searchBytes := func(needle []byte) {
				if len(needle) == 0 {
					return
				}
				start := 0
				for matchesInRegion < opts.MaxMatchesPerPattern {
					idx := indexBytes(buf[start:], needle)
					if idx < 0 {
						return
					}
					abs := start + idx
					hits = append(hits, Match{
						PatternName: p.Name,
						Severity:    p.Severity,
						Description: p.Description,
						Address:     r.Start + uint64(abs),
						Region:      regionTag(r),
						Excerpt:     excerpt(buf, abs, len(needle)),
					})
					matchesInRegion++
					start = abs + 1
				}
			}
			switch {
			case p.Bytes != nil:
				searchBytes(p.Bytes)
			case p.Regex != nil:
				idxs := p.Regex.FindAllIndex(buf, opts.MaxMatchesPerPattern)
				for _, m := range idxs {
					hits = append(hits, Match{
						PatternName: p.Name,
						Severity:    p.Severity,
						Description: p.Description,
						Address:     r.Start + uint64(m[0]),
						Region:      regionTag(r),
						Excerpt:     excerpt(buf, m[0], m[1]-m[0]),
					})
				}
			}
		}
	}
	return hits, nil
}

// region is one /proc/<pid>/maps entry.
type region struct {
	Start, End uint64
	Readable   bool
	Writable   bool
	Executable bool
	Private    bool
	Tag        string // e.g., "[heap]", "[stack]", "[vdso]" or pathname
	Special    bool   // any [bracketed] mapping
}

func readMaps(pid int) ([]region, error) {
	body, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	return parseMapsLines(body), nil
}

// parseMapsLines is the pure parser for the /proc/<pid>/maps text
// format. Split out so it's testable and fuzzable without touching
// the filesystem.
//
// Malformed lines are skipped silently; the parser must never panic
// regardless of input (kernel format is stable, but namespaced procfs,
// container shims, and partial reads can still deliver garbage).
func parseMapsLines(body []byte) []region {
	var out []region
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 1<<16), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		dash := strings.IndexByte(fields[0], '-')
		if dash < 0 {
			continue
		}
		start, err1 := strconv.ParseUint(fields[0][:dash], 16, 64)
		end, err2 := strconv.ParseUint(fields[0][dash+1:], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		perms := fields[1]
		if len(perms) < 4 {
			continue
		}
		r := region{
			Start:      start,
			End:        end,
			Readable:   perms[0] == 'r',
			Writable:   perms[1] == 'w',
			Executable: perms[2] == 'x',
			Private:    perms[3] == 'p',
		}
		if len(fields) >= 6 {
			r.Tag = fields[5]
			r.Special = strings.HasPrefix(r.Tag, "[") && strings.HasSuffix(r.Tag, "]")
		}
		out = append(out, r)
	}
	return out
}

func regionTag(r region) string {
	if r.Tag != "" {
		return r.Tag
	}
	switch {
	case r.Writable && r.Executable:
		return "anon-rwx"
	case r.Writable:
		return "anon-rw"
	case r.Executable:
		return "anon-rx"
	default:
		return "anon-ro"
	}
}

// indexBytes returns the index of the first occurrence of needle in
// haystack, or -1 if absent.
//
// Earlier this was a hand-rolled loop with an off-by-one bug:
// for a 2-byte needle the inner loop "for j := 1; j < last" had
// last==1 and ran zero iterations, so any (a, *) where a==needle[0]
// produced a false match. Replaced with bytes.Index — the original
// "avoid the import" rationale was spurious (no cycle exists).
func indexBytes(haystack, needle []byte) int {
	// Preserve the prior contract: empty needle is a programming
	// error, return -1 rather than bytes.Index's "found at 0".
	if len(needle) == 0 {
		return -1
	}
	return bytes.Index(haystack, needle)
}

func excerpt(buf []byte, at, hitLen int) string {
	const span = 32
	lo := at - span
	if lo < 0 {
		lo = 0
	}
	hi := at + hitLen + span
	if hi > len(buf) {
		hi = len(buf)
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 0, (hi-lo)*2)
	for _, c := range buf[lo:hi] {
		out = append(out, hex[c>>4], hex[c&0x0f])
	}
	return string(out)
}

// DefaultPatterns returns a small starting set of high-signal,
// low-false-positive patterns. Operators are expected to extend this
// with their own. The set is intentionally tiny; YARA is the right
// tool when you need 1000 rules.
func DefaultPatterns() []Pattern {
	return []Pattern{
		{
			Name:        "shellcode_x64_setuid0",
			Severity:    "critical",
			Description: "x86_64 syscall stub for setuid(0): mov rdi,0; mov rax,105; syscall",
			Bytes:       []byte{0x48, 0x31, 0xff, 0xb8, 0x69, 0x00, 0x00, 0x00, 0x0f, 0x05},
		},
		{
			Name:        "shellcode_execve_binsh",
			Severity:    "critical",
			Description: "/bin/sh string commonly embedded in shellcode",
			Bytes:       []byte("/bin/sh\x00"),
		},
		{
			Name:        "shellcode_meterpreter_uri",
			Severity:    "critical",
			Description: "Meterpreter HTTP staging URI fragment",
			Regex:       regexp.MustCompile(`/[a-zA-Z0-9_-]{4}_[A-Za-z0-9]{16,32}/`),
		},
		{
			Name:        "shellcode_x64_shell_revtcp",
			Severity:    "critical",
			Description: "Common reverse-TCP shellcode prologue (xor rax,rax; mov rdi,2; mov rsi,1)",
			Bytes:       []byte{0x48, 0x31, 0xc0, 0x48, 0xff, 0xc0, 0x48, 0x89, 0xc7},
		},
		{
			Name:        "ld_preload_env",
			Severity:    "warning",
			Description: "LD_PRELOAD set in process environment (may be legitimate)",
			Bytes:       []byte("LD_PRELOAD="),
		},
	}
}
