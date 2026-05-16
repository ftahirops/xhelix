package knowngood

// NewDefault returns a corpus seeded with the project's bundled
// catalog of legitimate-service endpoints. Entries here are factual:
// they describe public-DNS suffixes operated by well-known service
// providers, written down so the verdict engine can recognise common
// traffic without per-host configuration.
//
// Operators can extend the corpus at runtime via Corpus.Add.
func NewDefault() *Corpus {
	c := New()

	// ─── OS / system services ──────────────────────────────────────
	// Ubuntu / Canonical
	c.Add(Entry{Pattern: "*.ubuntu.com", Category: "os-update", Confidence: "verified", Note: "Ubuntu archives + livepatch"})
	c.Add(Entry{Pattern: "*.canonical.com", Category: "os-update", Confidence: "verified"})
	c.Add(Entry{Pattern: "*.launchpad.net", Category: "os-update", Confidence: "verified"})
	c.Add(Entry{Pattern: "*.snapcraft.io", Category: "os-update", Confidence: "verified", Note: "Snap store"})
	// Debian
	c.Add(Entry{Pattern: "*.debian.org", Category: "os-update", Confidence: "verified"})
	// Fedora / Red Hat
	c.Add(Entry{Pattern: "*.fedoraproject.org", Category: "os-update", Confidence: "verified"})
	c.Add(Entry{Pattern: "*.redhat.com", Category: "os-update", Confidence: "verified"})
	c.Add(Entry{Pattern: "*.centos.org", Category: "os-update", Confidence: "verified"})
	// Arch
	c.Add(Entry{Pattern: "*.archlinux.org", Category: "os-update", Confidence: "verified"})

	// ─── Time + DNS infra ──────────────────────────────────────────
	c.Add(Entry{Pattern: "*.pool.ntp.org", Category: "time", Confidence: "verified"})
	c.Add(Entry{Pattern: "time.cloudflare.com", Category: "time", Confidence: "verified"})
	c.Add(Entry{Pattern: "time.google.com", Category: "time", Confidence: "verified"})
	// Public resolvers (operator may still want to block these — they
	// just are factually public DNS endpoints).
	c.Add(Entry{Pattern: "one.one.one.one", Category: "dns", Confidence: "verified", Note: "Cloudflare 1.1.1.1"})
	c.Add(Entry{Pattern: "dns.google", Category: "dns", Confidence: "verified"})
	c.Add(Entry{Pattern: "dns.quad9.net", Category: "dns", Confidence: "verified"})

	// ─── TLS / CRL / OCSP infrastructure ───────────────────────────
	c.Add(Entry{Pattern: "*.letsencrypt.org", Category: "tls-pki", Confidence: "verified"})
	c.Add(Entry{Pattern: "*.digicert.com", Category: "tls-pki", Confidence: "verified"})
	c.Add(Entry{Pattern: "*.sectigo.com", Category: "tls-pki", Confidence: "verified"})
	c.Add(Entry{Pattern: "*.pki.goog", Category: "tls-pki", Confidence: "verified"})

	// ─── Container registries / package managers (developer infra) ──
	c.Add(Entry{Pattern: "*.docker.io", Category: "package-registry", Confidence: "verified"})
	c.Add(Entry{Pattern: "*.docker.com", Category: "package-registry", Confidence: "verified"})
	c.Add(Entry{Pattern: "registry.npmjs.org", Category: "package-registry", Confidence: "verified"})
	c.Add(Entry{Pattern: "*.pypi.org", Category: "package-registry", Confidence: "verified"})
	c.Add(Entry{Pattern: "files.pythonhosted.org", Category: "package-registry", Confidence: "verified"})
	c.Add(Entry{Pattern: "rubygems.org", Category: "package-registry", Confidence: "verified"})
	c.Add(Entry{Pattern: "*.crates.io", Category: "package-registry", Confidence: "verified"})
	c.Add(Entry{Pattern: "proxy.golang.org", Category: "package-registry", Confidence: "verified"})
	c.Add(Entry{Pattern: "sum.golang.org", Category: "package-registry", Confidence: "verified"})

	// ─── Source forges ─────────────────────────────────────────────
	c.Add(Entry{Pattern: "*.github.com", Category: "source-forge", Confidence: "verified"})
	c.Add(Entry{Pattern: "*.githubusercontent.com", Category: "source-forge", Confidence: "verified"})
	c.Add(Entry{Pattern: "*.gitlab.com", Category: "source-forge", Confidence: "verified"})
	c.Add(Entry{Pattern: "*.bitbucket.org", Category: "source-forge", Confidence: "verified"})

	// ─── Big-CDN platform footprints ───────────────────────────────
	// These are very broad and may not be desirable to whitelist — the
	// operator can prune them. They are categorised as cdn-broad so
	// policy can opt out.
	c.Add(Entry{Pattern: "*.cloudflare.com", Category: "cdn-broad", Confidence: "verified"})
	c.Add(Entry{Pattern: "*.cloudfront.net", Category: "cdn-broad", Confidence: "verified"})
	c.Add(Entry{Pattern: "*.fastly.net", Category: "cdn-broad", Confidence: "verified"})
	c.Add(Entry{Pattern: "*.akamaized.net", Category: "cdn-broad", Confidence: "verified"})
	c.Add(Entry{Pattern: "*.akamai.net", Category: "cdn-broad", Confidence: "verified"})

	// ─── Search / well-known platforms (functional endpoints) ──────
	c.Add(Entry{Pattern: "*.google.com", Category: "platform", Confidence: "likely", Note: "Google search/services — broad"})
	c.Add(Entry{Pattern: "*.googleapis.com", Category: "platform", Confidence: "likely"})
	c.Add(Entry{Pattern: "*.gstatic.com", Category: "platform", Confidence: "likely"})
	c.Add(Entry{Pattern: "*.microsoft.com", Category: "platform", Confidence: "likely", Note: "Microsoft — broad"})
	c.Add(Entry{Pattern: "*.windows.com", Category: "platform", Confidence: "likely"})
	c.Add(Entry{Pattern: "*.apple.com", Category: "platform", Confidence: "likely"})
	c.Add(Entry{Pattern: "*.icloud.com", Category: "platform", Confidence: "likely"})
	c.Add(Entry{Pattern: "*.mozilla.org", Category: "platform", Confidence: "verified"})
	c.Add(Entry{Pattern: "*.mozilla.net", Category: "platform", Confidence: "verified"})

	// IP-prefix seeds — populated from a separate file so it stays readable.
	seedCIDRs(c)

	// ─── ASN-level entries for major public infra (broad fallback) ──
	// Operators can prune these. Listed by IANA-assigned ASN.
	c.Add(Entry{ASN: 13335, Pattern: "", Category: "cdn-broad", Confidence: "verified", Note: "Cloudflare"})
	c.Add(Entry{ASN: 16509, Pattern: "", Category: "cdn-broad", Confidence: "likely", Note: "Amazon AWS"})
	c.Add(Entry{ASN: 15169, Pattern: "", Category: "cdn-broad", Confidence: "likely", Note: "Google"})
	c.Add(Entry{ASN: 8075, Pattern: "", Category: "cdn-broad", Confidence: "likely", Note: "Microsoft"})

	return c
}
