package telemetrycorpus

// NewDefault returns a corpus seeded with the project's bundled
// catalog of telemetry / analytics / tracker endpoints.
//
// These are factual references to DNS suffixes used by named
// products for non-functional traffic. Operators can extend the
// corpus at runtime via Corpus.Add or by editing the bundled YAML
// at /etc/xhelix/telemetry.d/*.yaml.
func NewDefault() *Corpus {
	c := New()

	// ─── Generic analytics platforms ───────────────────────────────
	c.Add(Entry{Pattern: "*.google-analytics.com", Product: "GoogleAnalytics", Category: CatAnalytics})
	c.Add(Entry{Pattern: "*.googletagmanager.com", Product: "GoogleTagManager", Category: CatAnalytics})
	c.Add(Entry{Pattern: "*.analytics.google.com", Product: "GA4", Category: CatAnalytics})
	c.Add(Entry{Pattern: "*.doubleclick.net", Product: "GoogleAds", Category: CatAds})
	c.Add(Entry{Pattern: "*.googlesyndication.com", Product: "GoogleAdSense", Category: CatAds})
	c.Add(Entry{Pattern: "*.adservice.google.com", Product: "GoogleAds", Category: CatAds})

	c.Add(Entry{Pattern: "*.segment.io", Product: "Segment", Category: CatAnalytics})
	c.Add(Entry{Pattern: "*.segment.com", Product: "Segment", Category: CatAnalytics})
	c.Add(Entry{Pattern: "*.mixpanel.com", Product: "Mixpanel", Category: CatAnalytics})
	c.Add(Entry{Pattern: "*.amplitude.com", Product: "Amplitude", Category: CatAnalytics})
	c.Add(Entry{Pattern: "*.posthog.com", Product: "PostHog", Category: CatAnalytics})
	c.Add(Entry{Pattern: "*.heap.io", Product: "Heap", Category: CatAnalytics})
	c.Add(Entry{Pattern: "*.hotjar.com", Product: "Hotjar", Category: CatTracker})
	c.Add(Entry{Pattern: "*.fullstory.com", Product: "FullStory", Category: CatTracker})
	c.Add(Entry{Pattern: "*.intercom.io", Product: "Intercom", Category: CatTracker})
	c.Add(Entry{Pattern: "*.statsig.com", Product: "Statsig", Category: CatAnalytics})

	// Crash reporting
	c.Add(Entry{Pattern: "*.sentry.io", Product: "Sentry", Category: CatCrash})
	c.Add(Entry{Pattern: "*.bugsnag.com", Product: "Bugsnag", Category: CatCrash})
	c.Add(Entry{Pattern: "*.rollbar.com", Product: "Rollbar", Category: CatCrash})
	c.Add(Entry{Pattern: "*.crashlytics.com", Product: "Crashlytics", Category: CatCrash})
	c.Add(Entry{Pattern: "*.firebaseio.com", Product: "Firebase", Category: CatAnalytics})
	c.Add(Entry{Pattern: "*.crashpad.chromium.org", Product: "Chromium", Category: CatCrash})

	// Ad-trackers
	c.Add(Entry{Pattern: "*.scorecardresearch.com", Product: "Comscore", Category: CatTracker})
	c.Add(Entry{Pattern: "*.quantserve.com", Product: "Quantcast", Category: CatTracker})
	c.Add(Entry{Pattern: "*.criteo.com", Product: "Criteo", Category: CatAds})
	c.Add(Entry{Pattern: "*.taboola.com", Product: "Taboola", Category: CatAds})
	c.Add(Entry{Pattern: "*.outbrain.com", Product: "Outbrain", Category: CatAds})

	// Meta / Facebook
	c.Add(Entry{Pattern: "*.facebook.net", Product: "Meta", Category: CatTracker, Note: "Facebook Pixel"})
	c.Add(Entry{Pattern: "*.fbcdn.net", Product: "Meta", Category: CatTracker})
	c.Add(Entry{Pattern: "graph.facebook.com", Product: "Meta", Category: CatTracker, Note: "Graph API"})

	// ─── Microsoft / Windows / Office telemetry ────────────────────
	c.Add(Entry{Pattern: "*.events.data.microsoft.com", Product: "Windows", Category: CatTelemetry, Note: "Universal Telemetry Client"})
	c.Add(Entry{Pattern: "*.vortex.data.microsoft.com", Product: "Windows", Category: CatTelemetry})
	c.Add(Entry{Pattern: "*.telecommand.telemetry.microsoft.com", Product: "Windows", Category: CatTelemetry})
	c.Add(Entry{Pattern: "*.watson.telemetry.microsoft.com", Product: "Windows", Category: CatCrash, Note: "Windows Error Reporting"})
	c.Add(Entry{Pattern: "settings-win.data.microsoft.com", Product: "Windows", Category: CatTelemetry})
	c.Add(Entry{Pattern: "*.dc.services.visualstudio.com", Product: "VSCode", Category: CatTelemetry, Note: "App Insights — VSCode + many MS products"})
	c.Add(Entry{Pattern: "*.applicationinsights.azure.com", Product: "AppInsights", Category: CatTelemetry})
	c.Add(Entry{Pattern: "*.in.applicationinsights.azure.com", Product: "AppInsights", Category: CatTelemetry})
	c.Add(Entry{Pattern: "*.live.com", Product: "Microsoft", Category: CatTelemetry, Note: "Various Live services — broad"})
	c.Add(Entry{Pattern: "*.officeapps.live.com", Product: "Office", Category: CatTelemetry})
	c.Add(Entry{Pattern: "*.office.com", Product: "Office", Category: CatTelemetry, Note: "Office signals — broad"})
	c.Add(Entry{Pattern: "*.bingapis.com", Product: "Bing", Category: CatTelemetry})

	// ─── Apple telemetry ────────────────────────────────────────────
	c.Add(Entry{Pattern: "*.apple.com.akadns.net", Product: "Apple", Category: CatTelemetry, Note: "Akamai-hosted Apple services"})
	c.Add(Entry{Pattern: "diagnostics.apple.com", Product: "Apple", Category: CatTelemetry})
	c.Add(Entry{Pattern: "metrics.apple.com", Product: "Apple", Category: CatTelemetry})
	c.Add(Entry{Pattern: "*.metrics.icloud.com", Product: "iCloud", Category: CatTelemetry})

	// ─── Google / Chrome / ChromeOS ────────────────────────────────
	c.Add(Entry{Pattern: "clients2.google.com", Product: "Chrome", Category: CatTelemetry, Note: "Update + safe-browsing"})
	c.Add(Entry{Pattern: "clients4.google.com", Product: "Chrome", Category: CatTelemetry})
	c.Add(Entry{Pattern: "*.update.googleapis.com", Product: "Chrome", Category: CatTelemetry, Note: "Omaha update"})
	c.Add(Entry{Pattern: "*.gvt1.com", Product: "Chrome", Category: CatTelemetry, Note: "Google update infrastructure"})
	c.Add(Entry{Pattern: "*.gvt2.com", Product: "Chrome", Category: CatTelemetry})
	c.Add(Entry{Pattern: "tools.google.com", Product: "Chrome", Category: CatTelemetry})
	c.Add(Entry{Pattern: "*.metric.gstatic.com", Product: "Chrome", Category: CatTelemetry})
	c.Add(Entry{Pattern: "*.chromeexperiments.com", Product: "Chrome", Category: CatTelemetry})

	// ─── Firefox / Mozilla ─────────────────────────────────────────
	c.Add(Entry{Pattern: "*.telemetry.mozilla.org", Product: "Firefox", Category: CatTelemetry})
	c.Add(Entry{Pattern: "incoming.telemetry.mozilla.org", Product: "Firefox", Category: CatTelemetry})
	c.Add(Entry{Pattern: "*.services.mozilla.com", Product: "Firefox", Category: CatTelemetry, Note: "Sync + push + accounts"})
	c.Add(Entry{Pattern: "shavar.services.mozilla.com", Product: "Firefox", Category: CatTracker, Note: "tracking-protection lists (functional)"})
	c.Add(Entry{Pattern: "*.cdn.mozilla.net", Product: "Firefox", Category: CatTelemetry})

	// ─── Ubuntu / Canonical telemetry ──────────────────────────────
	c.Add(Entry{Pattern: "popcon.ubuntu.com", Product: "Ubuntu", Category: CatTelemetry, Note: "popularity-contest"})
	c.Add(Entry{Pattern: "metrics.ubuntu.com", Product: "Ubuntu", Category: CatTelemetry})
	c.Add(Entry{Pattern: "motd.ubuntu.com", Product: "Ubuntu", Category: CatTelemetry, Note: "Message-of-the-day phone-home"})
	c.Add(Entry{Pattern: "daisy.ubuntu.com", Product: "Ubuntu", Category: CatCrash, Note: "apport crash submission"})
	c.Add(Entry{Pattern: "errors.ubuntu.com", Product: "Ubuntu", Category: CatCrash})
	c.Add(Entry{Pattern: "contracts.canonical.com", Product: "Ubuntu", Category: CatTelemetry})

	// ─── Snap / Flatpak ─────────────────────────────────────────────
	c.Add(Entry{Pattern: "api.snapcraft.io", Product: "Snap", Category: CatTelemetry, Note: "store calls"})
	c.Add(Entry{Pattern: "dashboard.snapcraft.io", Product: "Snap", Category: CatTelemetry})
	c.Add(Entry{Pattern: "*.flathub.org", Product: "Flatpak", Category: CatTelemetry})

	// ─── IDEs and editors ──────────────────────────────────────────
	// JetBrains
	c.Add(Entry{Pattern: "*.jetbrains.com", Product: "JetBrains", Category: CatTelemetry, Note: "broad — includes update + analytics"})
	c.Add(Entry{Pattern: "data.services.jetbrains.com", Product: "JetBrains", Category: CatTelemetry})
	c.Add(Entry{Pattern: "*.uxfeedback.ru", Product: "JetBrains", Category: CatAnalytics})
	c.Add(Entry{Pattern: "*.crashlytics.com", Product: "JetBrains", Category: CatCrash})
	// VS Code
	c.Add(Entry{Pattern: "vscode-update.azurewebsites.net", Product: "VSCode", Category: CatTelemetry, Note: "update channel"})
	c.Add(Entry{Pattern: "*.gallerycdn.vsassets.io", Product: "VSCode", Category: CatTelemetry, Note: "extension gallery"})
	c.Add(Entry{Pattern: "marketplace.visualstudio.com", Product: "VSCode", Category: CatTelemetry})
	c.Add(Entry{Pattern: "*.copilot-proxy.githubusercontent.com", Product: "Copilot", Category: CatTelemetry})

	// ─── Chat / video apps ─────────────────────────────────────────
	c.Add(Entry{Pattern: "*.slack.com", Product: "Slack", Category: CatTelemetry, Note: "functional + analytics — broad"})
	c.Add(Entry{Pattern: "*.slack-edge.com", Product: "Slack", Category: CatAnalytics})
	c.Add(Entry{Pattern: "*.discord.com", Product: "Discord", Category: CatTelemetry, Note: "broad — functional + analytics"})
	c.Add(Entry{Pattern: "*.discord-attachments-uploads.com", Product: "Discord", Category: CatAnalytics})
	c.Add(Entry{Pattern: "*.zoom.us", Product: "Zoom", Category: CatTelemetry, Note: "broad"})

	// ─── Media / cloud ─────────────────────────────────────────────
	c.Add(Entry{Pattern: "*.spclient.wg.spotify.com", Product: "Spotify", Category: CatAnalytics})
	c.Add(Entry{Pattern: "spclient.wg.spotify.com", Product: "Spotify", Category: CatAnalytics})
	c.Add(Entry{Pattern: "*.steam-chat.com", Product: "Steam", Category: CatAnalytics})
	c.Add(Entry{Pattern: "steamcommunity.com", Product: "Steam", Category: CatAnalytics, Note: "broad"})

	// ─── DNS / DoH (operator may choose to keep or block) ───────────
	// These are factual — products that report telemetry via DoH-style
	// HTTPS POSTs to specific endpoints.
	c.Add(Entry{Pattern: "*.mozilla.cloudflare-dns.com", Product: "Firefox-DoH", Category: CatTelemetry})

	return c
}
