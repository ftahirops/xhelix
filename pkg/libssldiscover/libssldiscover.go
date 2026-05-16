// Package libssldiscover finds libssl-equivalent SSL_read symbols
// on the host so the eBPF uprobe loader can attach. Two paths:
//
//   - Shared library on disk (libssl.so.3, libssl.so.1.1,
//     libgnutls.so.30, etc.) — find a known basename in well-
//     known directories, parse ELF symbol table for SSL_read /
//     gnutls_record_recv / similar, return (path, offset).
//   - Statically-linked binary (Go's crypto/tls, BoringSSL
//     statically linked into Chromium) — we can't uprobe these,
//     so we report them and skip.
//
// Pure-Go via debug/elf. Linux-only build-tag-split: the
// shared-library walk uses /etc/ld.so.cache and /proc/<self>/maps
// patterns that are POSIX-specific. Non-Linux returns an empty
// result with no error.
package libssldiscover

import (
	"debug/elf"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Target is one resolved uprobe attachment site.
type Target struct {
	// LibPath is the absolute path to the shared library.
	LibPath string
	// Symbol is the resolved symbol name ("SSL_read",
	// "gnutls_record_recv", etc.).
	Symbol string
	// Offset is the byte offset of the symbol from the start of
	// the ELF binary — what uprobe attachment expects.
	Offset uint64
	// Family identifies the TLS library implementation.
	Family Family
}

// Family classifies the underlying TLS implementation.
type Family string

const (
	FamilyOpenSSL Family = "openssl"
	FamilyGnuTLS  Family = "gnutls"
	FamilyNSS     Family = "nss"
	FamilyMbedTLS Family = "mbedtls"
	FamilyUnknown Family = "unknown"
)

// DefaultSearchPaths are the well-known directories where shared
// libraries land on common distros.
var DefaultSearchPaths = []string{
	"/usr/lib/x86_64-linux-gnu",
	"/usr/lib/aarch64-linux-gnu",
	"/usr/lib64",
	"/usr/lib",
	"/lib/x86_64-linux-gnu",
	"/lib/aarch64-linux-gnu",
	"/lib64",
	"/lib",
	"/opt/openssl/lib",
	"/usr/local/lib",
	"/usr/local/lib64",
}

// libCatalog maps glob-able file-basename patterns to the symbol
// name we want and the family it belongs to. Multiple entries
// can match — the discoverer returns one Target per matched lib.
type libEntry struct {
	prefix string // basename prefix to match (e.g. "libssl.so")
	symbol string // canonical symbol to find
	family Family
}

var libCatalog = []libEntry{
	{prefix: "libssl.so", symbol: "SSL_read", family: FamilyOpenSSL},
	{prefix: "libssl.so", symbol: "SSL_read_ex", family: FamilyOpenSSL}, // OpenSSL 3.x variant
	{prefix: "libgnutls.so", symbol: "gnutls_record_recv", family: FamilyGnuTLS},
	{prefix: "libnss3.so", symbol: "SSL_Read", family: FamilyNSS},
	{prefix: "libmbedtls.so", symbol: "mbedtls_ssl_read", family: FamilyMbedTLS},
}

// Discover walks the search paths and returns every Target
// matching the catalog. Paths defaults to DefaultSearchPaths when
// nil. Errors on individual libraries are non-fatal — they get
// skipped with no error returned, since a host with one broken
// libssl shouldn't fail the discovery for the others.
func Discover(paths []string) []Target {
	if paths == nil {
		paths = DefaultSearchPaths
	}
	seen := map[string]struct{}{}
	var out []Target
	for _, dir := range paths {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			for _, cat := range libCatalog {
				if !strings.HasPrefix(name, cat.prefix) {
					continue
				}
				abs := filepath.Join(dir, name)
				if _, dup := seen[abs+"|"+cat.symbol]; dup {
					continue
				}
				seen[abs+"|"+cat.symbol] = struct{}{}
				off, err := ResolveSymbol(abs, cat.symbol)
				if err != nil {
					continue
				}
				out = append(out, Target{
					LibPath: abs, Symbol: cat.symbol,
					Offset: off, Family: cat.family,
				})
			}
		}
	}
	return out
}

// DiscoverSingle returns the first matching Target for a single
// library basename pattern. Useful for tests + when an operator
// wants only OpenSSL.
func DiscoverSingle(prefix string, paths []string) (Target, bool) {
	if paths == nil {
		paths = DefaultSearchPaths
	}
	for _, dir := range paths {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), prefix) {
				continue
			}
			abs := filepath.Join(dir, e.Name())
			for _, cat := range libCatalog {
				if cat.prefix != prefix {
					continue
				}
				off, err := ResolveSymbol(abs, cat.symbol)
				if err != nil {
					continue
				}
				return Target{
					LibPath: abs, Symbol: cat.symbol,
					Offset: off, Family: cat.family,
				}, true
			}
		}
	}
	return Target{}, false
}

// ResolveSymbol opens an ELF file and returns the byte offset of
// the named symbol. Walks both `.dynsym` and `.symtab`.
func ResolveSymbol(path, name string) (uint64, error) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	// .dynsym (the dynamic symbol table — present on stripped libs).
	dyn, err := f.DynamicSymbols()
	if err == nil {
		for _, s := range dyn {
			if s.Name == name && s.Value != 0 {
				return s.Value, nil
			}
		}
	}
	// .symtab (the full symbol table — usually only on unstripped).
	syms, err := f.Symbols()
	if err == nil {
		for _, s := range syms {
			if s.Name == name && s.Value != 0 {
				return s.Value, nil
			}
		}
	}
	return 0, errors.New("libssldiscover: symbol not found: " + name)
}

// IsLikelyStaticBinary reports whether the given executable is
// statically linked. Useful for the daemon to detect Go / Rust
// binaries that uprobe can't reach.
func IsLikelyStaticBinary(path string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	// A dynamically-linked ELF has a PT_INTERP segment with the
	// dynamic linker path. Absence of PT_INTERP is the classic
	// "fully static" indicator.
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return false
		}
	}
	return true
}

// LibraryReport is the operator-facing summary of what
// Discover found and what it skipped.
type LibraryReport struct {
	Targets         []Target
	Skipped         []string // basenames seen but symbol not resolvable
	StaticBinaries  []string // exe paths that won't be uprobed
}

// WalkInstalledExecutables scans /usr/bin + /usr/local/bin for
// statically-linked executables we can't uprobe, so the operator
// knows the libssl path won't cover them. Bounded by maxFiles.
func WalkInstalledExecutables(maxFiles int) []string {
	if maxFiles <= 0 {
		maxFiles = 1000
	}
	var out []string
	dirs := []string{"/usr/bin", "/usr/local/bin", "/usr/sbin"}
	count := 0
	for _, d := range dirs {
		_ = filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return nil
			}
			if count >= maxFiles {
				return filepath.SkipAll
			}
			if IsLikelyStaticBinary(p) {
				out = append(out, p)
			}
			count++
			return nil
		})
	}
	return out
}
