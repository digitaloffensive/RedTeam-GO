package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ANSI escape codes. All output goes through colorize() so they can be
// stripped cleanly when --no-color is set.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
	ansiGray   = "\033[90m"
)

var colorEnabled bool

func c(code, text string) string {
	if !colorEnabled {
		return text
	}
	return code + text + ansiReset
}

// PrintReport renders the full vetting report to stdout.
func PrintReport(r Report, color bool) {
	colorEnabled = color
	w := 66
	rule := strings.Repeat("━", w)

	// ── Header ────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println(c(ansiBold+ansiBlue, "╔"+strings.Repeat("═", w-2)+"╗"))
	header := "  DOMAIN VETTING REPORT  "
	pad := w - 2 - len(header)
	left := pad / 2
	right := pad - left
	fmt.Println(c(ansiBold+ansiBlue, "║"+strings.Repeat(" ", left)+header+strings.Repeat(" ", right)+"║"))
	fmt.Println(c(ansiBold+ansiBlue, "╚"+strings.Repeat("═", w-2)+"╝"))
	fmt.Printf("  %s  %s\n", c(ansiBold, "Target:"), r.Domain)
	fmt.Printf("  %s  %s\n\n", c(ansiBold, "Scanned:"), r.Timestamp.Format("2006-01-02 15:04:05 UTC"))

	// ── DNS Health ────────────────────────────────────────────────────
	printSection("DNS HEALTH", r.DNS.Score, r.DNS.MaxScore, rule)
	for _, ch := range r.DNS.Checks {
		printCheck(ch)
	}
	fmt.Println()

	// ── Blacklists ────────────────────────────────────────────────────
	printSection("BLACKLISTS", r.Blacklists.Score, r.Blacklists.MaxScore, rule)
	if r.Blacklists.IP != "" {
		fmt.Printf("  %s  %s\n\n", c(ansiGray, "Resolved IP"), r.Blacklists.IP)
	}
	if len(r.Blacklists.IPChecks) > 0 {
		fmt.Printf("  %s\n", c(ansiGray, "IP-Based (DNSBL)"))
		for _, e := range r.Blacklists.IPChecks {
			printBlacklistEntry(e)
		}
		fmt.Println()
	}
	if len(r.Blacklists.DomainChecks) > 0 {
		fmt.Printf("  %s\n", c(ansiGray, "Domain-Based (SURBL/DBL)"))
		for _, e := range r.Blacklists.DomainChecks {
			printBlacklistEntry(e)
		}
	}
	fmt.Println()

	// ── SSL Certificate ───────────────────────────────────────────────
	printSection("SSL CERTIFICATE", r.SSL.Score, r.SSL.MaxScore, rule)
	if r.SSL.Error != "" && len(r.SSL.Checks) == 0 {
		fmt.Printf("  %s  %s\n", c(ansiRed, "✗"), r.SSL.Error)
	} else {
		for _, ch := range r.SSL.Checks {
			printCheck(ch)
		}
	}
	fmt.Println()

	// ── Domain Age ────────────────────────────────────────────────────
	printSection("DOMAIN AGE", r.Age.Score, r.Age.MaxScore, rule)
	for _, ch := range r.Age.Checks {
		printCheck(ch)
	}
	fmt.Println()

	// ── VirusTotal (optional) ─────────────────────────────────────────
	if r.VT != nil {
		printSection("VIRUSTOTAL", r.VT.Score, r.VT.MaxScore, rule)
		for _, ch := range r.VT.Checks {
			printCheck(ch)
		}
		fmt.Println()
	}

	// ── Google Safe Browsing (optional) ───────────────────────────────
	if r.GSB != nil {
		printSection("GOOGLE SAFE BROWSING", r.GSB.Score, r.GSB.MaxScore, rule)
		for _, ch := range r.GSB.Checks {
			printCheck(ch)
		}
		fmt.Println()
	}

	// ── Overall Score ─────────────────────────────────────────────────
	fmt.Println(c(ansiBold, rule))
	scoreColor := verdictColor(r.Percentage)
	fmt.Printf("  %s   %s  (%.0f%%)\n",
		c(ansiBold, "OVERALL SCORE"),
		c(ansiBold+scoreColor, fmt.Sprintf("%d / %d", r.TotalScore, r.MaxScore)),
		r.Percentage,
	)
	fmt.Println(c(ansiBold, rule))
	fmt.Printf("\n  %s\n\n", verdictLine(r.Verdict, r.Percentage))

	// ── Recommendations ───────────────────────────────────────────────
	recs := buildRecommendations(r)
	if len(recs) > 0 {
		fmt.Println(c(ansiBold, "  Recommendations:"))
		for _, rec := range recs {
			fmt.Printf("    %s  %s\n", c(ansiCyan, "→"), rec)
		}
		fmt.Println()
	}
}

func printSection(title string, score, max int, rule string) {
	scoreStr := fmt.Sprintf("[%d/%d]", score, max)
	gap := 66 - 2 - len(title) - len(scoreStr)
	if gap < 1 {
		gap = 1
	}
	fmt.Println(c(ansiBold, rule))
	fmt.Printf("  %s%s%s\n", c(ansiBold+ansiCyan, title), strings.Repeat(" ", gap), scoreStr)
	fmt.Println(c(ansiBold, rule))
}

func printCheck(ch Check) {
	sym := statusSymbol(ch.Status)
	if ch.MaxPoints == 0 && ch.Status == Info {
		fmt.Printf("  %s  %-22s %s\n", c(ansiBlue, "i"), ch.Name, c(ansiGray, ch.Detail))
		return
	}
	fmt.Printf("  %s  %-22s %s\n", sym, ch.Name, ch.Detail)
}

func printBlacklistEntry(e BlacklistEntry) {
	if e.Listed {
		fmt.Printf("    %s  %-22s %s\n", c(ansiRed, "✗"), e.List, c(ansiRed, "LISTED"))
	} else if e.Response == "skipped — no IP resolved" {
		fmt.Printf("    %s  %-22s %s\n", c(ansiGray, "—"), e.List, c(ansiGray, "skipped"))
	} else {
		fmt.Printf("    %s  %-22s %s\n", c(ansiGreen, "✓"), e.List, c(ansiGreen, "Clean"))
	}
}

func statusSymbol(s Status) string {
	switch s {
	case Pass:
		return c(ansiGreen, "✓")
	case Warn:
		return c(ansiYellow, "⚠")
	case Fail:
		return c(ansiRed, "✗")
	case Skip:
		return c(ansiGray, "—")
	default:
		return c(ansiBlue, "i")
	}
}

func verdictColor(pct float64) string {
	switch {
	case pct >= 85:
		return ansiGreen
	case pct >= 50:
		return ansiYellow
	default:
		return ansiRed
	}
}

func verdictLine(verdict string, pct float64) string {
	color := verdictColor(pct)
	desc := map[string]string{
		"READY":        "Deploy with confidence — all critical checks passed",
		"LIKELY READY": "Minor issues to review before operational deployment",
		"CAUTION":      "Address flagged issues before operational use",
		"NOT READY":    "Significant issues detected — do not use operationally",
	}[verdict]
	return fmt.Sprintf("%s — %s", c(ansiBold+color, verdict), desc)
}

// buildRecommendations generates actionable next steps based on check results.
func buildRecommendations(r Report) []string {
	var recs []string

	for _, ch := range r.DNS.Checks {
		if ch.Status != Fail && ch.Status != Warn {
			continue
		}
		switch ch.Name {
		case "A Record":
			recs = append(recs, "Create an A record — domain must resolve to pass SEG checks")
		case "MX Record":
			recs = append(recs, "Configure MX records before sending email from this domain")
		case "SPF Record":
			recs = append(recs, "Add SPF: v=spf1 ip4:YOUR_SMTP_IP -all")
		case "DMARC Record":
			recs = append(recs, fmt.Sprintf("Add DMARC: v=DMARC1; p=quarantine; rua=mailto:dmarc@%s", r.Domain))
		case "DKIM Record":
			recs = append(recs, "Configure DKIM (OpenDKIM) and publish the selector TXT record")
		}
	}

	if r.Blacklists.TotalListed > 0 {
		recs = append(recs, fmt.Sprintf(
			"Resolve %d blacklist listing(s) — submit delisting requests to each provider",
			r.Blacklists.TotalListed,
		))
	}

	if !r.SSL.Valid {
		recs = append(recs, "Install a valid SSL certificate (ZeroSSL or paid DV cert recommended over Let's Encrypt)")
	} else {
		for _, ch := range r.SSL.Checks {
			if ch.Name == "Certificate Age" && ch.Status == Warn {
				recs = append(recs, fmt.Sprintf("Wait ~%d more days for cert to age past the 30-day threshold", 30-r.SSL.AgeDays))
			}
			if ch.Name == "Certificate Expiry" && (ch.Status == Warn || ch.Status == Fail) {
				recs = append(recs, "Renew SSL certificate before deployment")
			}
		}
	}

	if r.Age.Found {
		for _, ch := range r.Age.Checks {
			if ch.Name != "Domain Age" {
				continue
			}
			switch ch.Status {
			case Fail:
				days := 180 - r.Age.AgeDays
				if days < 0 {
					days = 0
				}
				recs = append(recs, fmt.Sprintf(
					"Domain too young — continue seeding; re-vet in ~%d days", days,
				))
			case Warn:
				recs = append(recs, "Domain maturing — move to Tier 1 inventory after 12+ months of age")
			}
		}
	} else {
		recs = append(recs, "WHOIS lookup failed — verify domain age manually at your registrar")
	}

	if r.VT != nil && r.VT.Malicious > 0 {
		recs = append(recs, fmt.Sprintf(
			"VirusTotal shows %d malicious detection(s) — investigate each engine before use", r.VT.Malicious,
		))
	}

	if r.GSB != nil && r.GSB.Flagged {
		recs = append(recs, "Domain is in Google Safe Browsing — this domain cannot be used for Gmail delivery")
		recs = append(recs, "Submit a false-positive report at safebrowsing.google.com/safebrowsing/report_error/")
	}

	return recs
}

// PrintJSON writes the report as indented JSON to stdout.
func printJSON(r Report) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(r)
}
