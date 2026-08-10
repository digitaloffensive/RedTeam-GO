# domainsvet

A command-line domain vetting tool for red team infrastructure assessment. Before an engagement starts, `domainsvet` tells you whether a domain is operationally ready — checking blacklist status, DNS health, SSL certificate age, domain registration age, and optional reputation APIs.

Built in Go. No external dependencies. Runs on macOS, Linux, and Windows.

---

## Why This Exists

Most red teams register a domain the morning of an engagement. That domain has no history, no categorization, no traffic pattern, and no trust — and every enterprise Secure Email Gateway (SEG) treats it as suspicious by default. `domainsvet` enforces a disciplined pre-engagement checklist so infrastructure issues never surface mid-operation.

---

## Checks

| Category | What's Checked | Max Score |
|---|---|---|
| **DNS Health** | A record, MX record, SPF, DMARC, DKIM (14 selectors) | 25 |
| **Blacklists** | 5 IP-based DNSBLs + 3 domain-based URI lists | 35 |
| **SSL Certificate** | Validity, issuer, cert age (>30d), expiry (>30d) | 20 |
| **Domain Age** | WHOIS registration date, tiered scoring | 20 |
| **VirusTotal** *(optional)* | Detection count via VT API v3 | +10 |
| **Google Safe Browsing** *(optional)* | Threat match via GSB Lookup API v4 | +10 |

### Blacklists Checked

**IP-based (DNSBL):** Spamhaus ZEN, SpamCop, SORBS, Barracuda, UCEProtect L1

**Domain-based (SURBL/DBL):** Spamhaus DBL, SURBL, URIBL Black

### Domain Age Scoring

| Age | Points | Verdict |
|---|---|---|
| 2+ years | 20 | Tier 1 ready |
| 1–2 years | 15 | Good for most engagements |
| 6–12 months | 10 | Caution — consider aging further |
| 3–6 months | 5 | Tier 2 candidate only |
| 1–3 months | 2 | Too young |
| < 30 days | 0 | Do not use |

### Overall Verdict

| Score | Verdict |
|---|---|
| 85–100% | **READY** — deploy with confidence |
| 70–84% | **LIKELY READY** — minor issues to review |
| 50–69% | **CAUTION** — address issues before operational use |
| < 50% | **NOT READY** — significant issues detected |

---

## Installation

### Build from source

Requires Go 1.21 or later.

```bash
git clone https://github.com/yourhandle/domainsvet
cd domainsvet
go build -o domainsvet .
```

### Cross-compile for all platforms

```bash
make build-all
```

Produces binaries in `dist/` for:
- `darwin/amd64` and `darwin/arm64` (macOS Intel + Apple Silicon)
- `linux/amd64` and `linux/arm64`
- `windows/amd64`

---

## Usage

```
domainsvet [flags] <domain>
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--vt-key` | — | VirusTotal API key (optional) |
| `--gsb-key` | — | Google Safe Browsing API key (optional) |
| `--timeout` | `10s` | Per-check network timeout |
| `--json` | false | Output results as JSON |
| `--no-color` | false | Disable colored terminal output |
| `--version` | — | Print version and exit |

### Examples

```bash
# Basic vet — no API keys required
./domainsvet example.com

# With VirusTotal and Google Safe Browsing
./domainsvet --vt-key YOUR_VT_KEY --gsb-key YOUR_GSB_KEY example.com

# JSON output — pipe-friendly
./domainsvet --json example.com

# Extract just the verdict
./domainsvet --json example.com | jq -r .verdict

# Vet multiple domains from a list
while read domain; do
  ./domainsvet --json "$domain" | jq -r '[.domain, .verdict, (.percentage|tostring + "%")] | @tsv'
done < domains.txt

# CI-friendly: exit 1 if domain is not ready
./domainsvet --json example.com | jq -e '.verdict == "READY"' > /dev/null
```

---

## Sample Output

```
╔════════════════════════════════════════════════════════════════╗
║                   DOMAIN VETTING REPORT                        ║
╚════════════════════════════════════════════════════════════════╝
  Target:   example.com
  Scanned:  2025-08-10 14:23:45 UTC

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  DNS HEALTH                                              [20/25]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✓  A Record               93.184.216.34
  ✓  MX Record              mail.example.com (priority 10)
  ✓  SPF Record             v=spf1 include:_spf.google.com ~all
  ✓  DMARC Record           v=DMARC1; p=quarantine; pct=100
  ⚠  DKIM Record            Not found (checked 14 selectors)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  BLACKLISTS                                              [28/35]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Resolved IP  93.184.216.34

  IP-Based (DNSBL)
    ✓  Spamhaus ZEN           Clean
    ✓  SpamCop                Clean
    ✓  SORBS                  Clean
    ✓  Barracuda              Clean
    ✓  UCEProtect L1          Clean

  Domain-Based (SURBL/DBL)
    ✓  Spamhaus DBL           Clean
    ✗  SURBL                  LISTED
    ✓  URIBL Black            Clean

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SSL CERTIFICATE                                         [15/20]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✓  Certificate Valid       Issuer: DigiCert Inc | Subject: example.com
  ⚠  Certificate Age         18 days old — recently issued cert is a SEG/sandbox signal
  ✓  Certificate Expiry      217 days remaining (expires 2026-03-15)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  DOMAIN AGE                                              [20/20]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✓  Domain Age              30 year(s) 0 month(s) old — strong trust signal
  i  Registrar               IANA

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  OVERALL SCORE   83 / 100  (83%)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  LIKELY READY — Minor issues to review before operational deployment

  Recommendations:
    →  Configure DKIM (OpenDKIM) and publish the selector TXT record
    →  Resolve 1 blacklist listing(s) — submit delisting requests to each provider
    →  Wait ~12 more days for cert to age past the 30-day threshold
```

---

## JSON Output Schema

```json
{
  "domain": "example.com",
  "timestamp": "2025-08-10T14:23:45Z",
  "dns": {
    "a_records": ["93.184.216.34"],
    "spf": "v=spf1 ...",
    "dmarc": "v=DMARC1; ...",
    "dkim_found": false,
    "score": 20,
    "max_score": 25
  },
  "blacklists": {
    "ip": "93.184.216.34",
    "total_listed": 1,
    "score": 28,
    "max_score": 35
  },
  "ssl": { "valid": true, "age_days": 18, "days_until_expiry": 217, "score": 15, "max_score": 20 },
  "age": { "found": true, "age_days": 10950, "score": 20, "max_score": 20 },
  "total_score": 83,
  "max_score": 100,
  "percentage": 83,
  "verdict": "LIKELY READY"
}
```

---

## API Keys

Both API integrations are entirely optional. Core checks run with no keys.

### VirusTotal

Free API keys available at [virustotal.com](https://www.virustotal.com). The free tier allows 4 lookups/minute, which is sufficient for pre-engagement vetting.

### Google Safe Browsing

Free API keys available via the [Google Cloud Console](https://developers.google.com/safe-browsing/v4/get-started). Enable the "Safe Browsing API" and create an API key with no restrictions for CLI use.

---

## Project Structure

```
domainsvet/
├── main.go           # Entry point, CLI flag parsing
├── types.go          # Shared structs and constants
├── scanner.go        # Orchestrates all checks, tallies score
├── dns.go            # A, MX, SPF, DMARC, DKIM checks
├── blacklist.go      # DNSBL and domain blacklist checks
├── ssl.go            # TLS certificate inspection
├── whois.go          # WHOIS protocol queries and date parsing
├── virustotal.go     # VirusTotal API v3 integration
├── safebrowsing.go   # Google Safe Browsing API v4 integration
├── report.go         # Terminal and JSON output formatting
├── Makefile          # Build and cross-compile targets
└── go.mod
```

---

## Background

`domainsvet` implements the domain infrastructure vetting criteria from *Initial Access Engineering: Building Custom Offensive Entry Frameworks* — a companion volume to *Evasion Engineering* (No Starch Press). The scoring model maps directly to the Chapter 1 domain readiness framework:

- **Tier 1** (READY): 85%+ score, 2+ year old domain, clean blacklists, aged SSL
- **Tier 2** (maturing): 50–84%, 3–12 month domain — continue seeding
- **Retire** (NOT READY): blacklisted, < 30 days old, or failed SSL

---

## Notes

- WHOIS lookups use the raw WHOIS protocol (TCP port 43) with IANA referral resolution. Some registries rate-limit WHOIS queries — if age checks fail intermittently, increase `--timeout`.
- SURBL and URIBL lookups may require a paid membership for high-volume use. Single pre-engagement checks are within free-tier limits.
- IPv6 addresses are skipped for DNSBL checks (most DNSBL zones are IPv4 only).
- Windows users: colored output requires Windows 10 version 1511 or later (VT processing enabled by default). Use `--no-color` on older systems.

---

## License

MIT
