package destclass

// Built-in suffix and CIDR tables. Deliberately small and curated.
// Production deployments will extend via WithExtraSuffixes /
// WithExtraCIDRs from /etc/xhelix/destclass.yaml or sync periodically
// from authoritative sources (AWS ip-ranges.json, Cloudflare CIDRs,
// Google's _cloud-netblocks DNS records).
//
// These defaults exist so the classifier returns sensible results on
// a fresh install with zero config.

func defaultRegistrySuffixes() []string {
	return []string{
		// Source control + git hosts
		"github.com", "githubusercontent.com", "githubassets.com",
		"gitlab.com", "bitbucket.org",
		"gitea.io", "codeberg.org", "sourcehut.org",
		// Language package registries
		"npmjs.org", "registry.npmjs.org", "yarnpkg.com",
		"pypi.org", "pythonhosted.org", "files.pythonhosted.org",
		"crates.io", "static.crates.io",
		"rubygems.org", "rubygems.global.ssl.fastly.net",
		"packagist.org", "repo.packagist.org",
		"hex.pm", "repo.hex.pm",
		"nuget.org", "api.nuget.org",
		"clojars.org", "repo1.maven.org", "maven.apache.org",
		"golang.org", "proxy.golang.org", "sum.golang.org",
		"hub.docker.com", "registry-1.docker.io", "auth.docker.io",
		"gcr.io", "k8s.gcr.io", "registry.k8s.io",
		"ghcr.io",
		"quay.io",
		"helm.sh", "charts.helm.sh",
		// Browser extension / IDE marketplaces
		"marketplace.visualstudio.com",
		"vscode-update.azurewebsites.net",
		"vscode.dev",
		"chrome.google.com", "clients2.google.com",
		"addons.mozilla.org",
	}
}

func defaultOSUpdateSuffixes() []string {
	return []string{
		// Debian / Ubuntu
		"debian.org", "deb.debian.org", "security.debian.org",
		"ubuntu.com", "archive.ubuntu.com", "security.ubuntu.com",
		"ports.ubuntu.com", "esm.ubuntu.com",
		// RHEL / Fedora / CentOS
		"redhat.com", "access.redhat.com", "cdn.redhat.com",
		"fedoraproject.org", "mirrors.fedoraproject.org",
		"centos.org", "vault.centos.org", "mirror.centos.org",
		"rockylinux.org", "almalinux.org",
		// SUSE
		"opensuse.org", "download.opensuse.org",
		"suse.com", "scc.suse.com",
		// Microsoft Update
		"microsoft.com", "windowsupdate.com", "update.microsoft.com",
		"download.microsoft.com",
		// Snap / Flatpak
		"snapcraft.io", "api.snapcraft.io",
		"flathub.org", "dl.flathub.org",
		// Apple (relevant on mac dev boxes)
		"apple.com", "swcdn.apple.com", "swdist.apple.com",
		// xhelix itself
		"xhelix.io",
	}
}

func defaultCDNSuffixes() []string {
	return []string{
		"cloudflare.com", "cloudflare.net", "cloudflareinsights.com",
		"akamai.net", "akamaized.net", "akamaihd.net", "akamaitechnologies.com",
		"fastly.net", "fastlylb.net",
		"cdn77.org",
		"cdninstagram.com",
		"jsdelivr.net", "cdn.jsdelivr.net",
		"unpkg.com",
		"bootstrapcdn.com",
		"cloudfront.net",
		"azureedge.net",
		"gstatic.com",
	}
}

func defaultCloudSuffixes() []string {
	return []string{
		// AWS
		"amazonaws.com", "aws.amazon.com",
		// GCP
		"googleapis.com", "googleusercontent.com",
		"cloud.google.com", "appspot.com", "run.app",
		// Azure
		"azure.com", "azurewebsites.net", "azure.net",
		"blob.core.windows.net", "core.windows.net",
		// DigitalOcean
		"digitaloceanspaces.com", "digitalocean.com",
		// Hetzner
		"hetzner.com", "your-server.de",
		// Linode / Akamai Cloud
		"linode.com", "linodeobjects.com",
	}
}

// defaultCloudCIDRs is a small seed list of well-known cloud-provider
// ranges. NOT exhaustive — production hosts should sync from
// authoritative sources (AWS ip-ranges.json etc.). The seeds cover
// the most common us-east / us-central regions so testing works
// out of the box.
func defaultCloudCIDRs() []string {
	return []string{
		// AWS — small seed (real one is ~5000 CIDRs from ip-ranges.json)
		"3.0.0.0/9",          // ec2 us-east, us-west
		"13.32.0.0/15",       // cloudfront edge (also CDN)
		"15.220.0.0/14",      // ec2 us-east-1
		"18.130.0.0/16",      // ec2 eu-west-2
		"34.192.0.0/12",      // ec2 us-east-1, us-west
		"52.0.0.0/12",        // big legacy block (multiple regions)
		"54.144.0.0/12",      // ec2 us-east
		// GCP — small seed
		"34.64.0.0/10",       // GCE multiple regions
		"35.184.0.0/13",      // GCE us-central
		"35.190.0.0/17",      // appspot, run.app
		// Azure — small seed
		"13.64.0.0/11",       // azure multiple regions
		"20.0.0.0/8",         // huge azure block (multiple regions)
		"40.64.0.0/10",       // azure
		// Hetzner — small seed (relevant: plesk.douxl.com sits here)
		"65.108.0.0/15",      // hetzner finland (the prod host)
		"95.216.0.0/15",      // hetzner finland
		"116.202.0.0/15",     // hetzner germany
		"168.119.0.0/16",     // hetzner germany
		// DigitalOcean — small seed
		"104.131.0.0/16", "138.197.0.0/16", "159.65.0.0/16",
		"165.227.0.0/16", "167.99.0.0/16", "188.166.0.0/16",
	}
}

// defaultCDNCIDRs is similarly a small seed.
func defaultCDNCIDRs() []string {
	return []string{
		// Cloudflare
		"103.21.244.0/22", "103.22.200.0/22", "104.16.0.0/13",
		"104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22",
		"141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13",
		"173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20",
		"197.234.240.0/22", "198.41.128.0/17",
		// Fastly
		"23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
		"103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
		"146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18",
		"167.82.0.0/17", "167.82.128.0/20", "167.82.160.0/20",
		"167.82.224.0/20", "172.111.64.0/18", "185.31.16.0/22",
		"199.27.72.0/21", "199.232.0.0/16",
		// Akamai
		"23.32.0.0/11", "23.192.0.0/11", "104.64.0.0/10",
		"184.24.0.0/13", "184.50.0.0/15", "184.84.0.0/14",
		// CloudFront (AWS)
		"54.182.0.0/16", "54.192.0.0/16", "54.230.0.0/16",
		"54.239.128.0/18", "143.204.0.0/16",
	}
}
