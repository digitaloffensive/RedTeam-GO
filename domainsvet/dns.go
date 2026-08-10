package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Common DKIM selectors to probe. Covers Google Workspace, Microsoft 365,
// Proofpoint, Mimecast, and generic defaults.
var dkimSelectors = []string{
	"default", "mail", "google", "smtp", "dkim",
	"k1", "selector1", "selector2", "email",
	"s1", "s2", "pm", "mimecast", "proofpoint",
}

// CheckDNS performs A, MX, SPF, DMARC, and DKIM health checks.
// Scoring: A(5) + MX(5) + SPF(5) + DMARC(5) + DKIM(5) = 25 points max.
func CheckDNS(domain string, timeout time.Duration) DNSResult {
	result := DNSResult{MaxScore: 25}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	r := net.DefaultResolver

	// ── A Records ────────────────────────────────────────────── 5 pts ──
	addrs, err := r.LookupHost(ctx, domain)
	if err == nil && len(addrs) > 0 {
		// Filter to IPv4 only for blacklist checks downstream
		var ipv4 []string
		for _, a := range addrs {
			if !strings.Contains(a, ":") {
				ipv4 = append(ipv4, a)
			}
		}
		result.ARecords = ipv4
		result.Checks = append(result.Checks, Check{
			Name:      "A Record",
			Status:    Pass,
			Detail:    strings.Join(ipv4, ", "),
			Points:    5,
			MaxPoints: 5,
		})
		result.Score += 5
	} else {
		result.Checks = append(result.Checks, Check{
			Name:      "A Record",
			Status:    Fail,
			Detail:    "No A records found — domain does not resolve",
			Points:    0,
			MaxPoints: 5,
		})
	}

	// ── MX Records ───────────────────────────────────────────── 5 pts ──
	mxRecords, err := r.LookupMX(ctx, domain)
	if err == nil && len(mxRecords) > 0 {
		primary := fmt.Sprintf("%s (priority %d)", mxRecords[0].Host, mxRecords[0].Pref)
		for _, mx := range mxRecords {
			result.MXRecords = append(result.MXRecords,
				fmt.Sprintf("%s (priority %d)", mx.Host, mx.Pref))
		}
		result.Checks = append(result.Checks, Check{
			Name:      "MX Record",
			Status:    Pass,
			Detail:    primary,
			Points:    5,
			MaxPoints: 5,
		})
		result.Score += 5
	} else {
		result.Checks = append(result.Checks, Check{
			Name:      "MX Record",
			Status:    Warn,
			Detail:    "No MX records — configure if sending mail from this domain",
			Points:    0,
			MaxPoints: 5,
		})
	}

	// ── SPF ──────────────────────────────────────────────────── 5 pts ──
	spf := lookupSPF(ctx, r, domain)
	result.SPF = spf
	if spf != "" {
		detail := trunc(spf, 72)
		if strings.Contains(spf, "-all") {
			detail += "  [hard fail: -all]"
		} else if strings.Contains(spf, "~all") {
			detail += "  [soft fail: ~all — consider -all]"
		}
		result.Checks = append(result.Checks, Check{
			Name:      "SPF Record",
			Status:    Pass,
			Detail:    detail,
			Points:    5,
			MaxPoints: 5,
		})
		result.Score += 5
	} else {
		result.Checks = append(result.Checks, Check{
			Name:      "SPF Record",
			Status:    Fail,
			Detail:    "No SPF record — add: v=spf1 ip4:YOUR_SMTP_IP -all",
			Points:    0,
			MaxPoints: 5,
		})
	}

	// ── DMARC ────────────────────────────────────────────────── 5 pts ──
	dmarc := lookupDMARC(ctx, r, domain)
	result.DMARC = dmarc
	if dmarc != "" {
		detail := trunc(dmarc, 72)
		if strings.Contains(dmarc, "p=none") {
			detail += "  [policy: none — upgrade to quarantine/reject]"
		}
		result.Checks = append(result.Checks, Check{
			Name:      "DMARC Record",
			Status:    Pass,
			Detail:    detail,
			Points:    5,
			MaxPoints: 5,
		})
		result.Score += 5
	} else {
		result.Checks = append(result.Checks, Check{
			Name:      "DMARC Record",
			Status:    Fail,
			Detail:    fmt.Sprintf("No DMARC record at _dmarc.%s", domain),
			Points:    0,
			MaxPoints: 5,
		})
	}

	// ── DKIM ─────────────────────────────────────────────────── 5 pts ──
	selector, found := lookupDKIM(ctx, r, domain)
	result.DKIMFound = found
	result.DKIMSelector = selector
	if found {
		result.Checks = append(result.Checks, Check{
			Name:      "DKIM Record",
			Status:    Pass,
			Detail:    fmt.Sprintf("Selector '%s' found at %s._domainkey.%s", selector, selector, domain),
			Points:    5,
			MaxPoints: 5,
		})
		result.Score += 5
	} else {
		result.Checks = append(result.Checks, Check{
			Name:      "DKIM Record",
			Status:    Warn,
			Detail:    fmt.Sprintf("Not found (checked %d selectors: %s)", len(dkimSelectors), strings.Join(dkimSelectors, ", ")),
			Points:    0,
			MaxPoints: 5,
		})
	}

	return result
}

func lookupSPF(ctx context.Context, r *net.Resolver, domain string) string {
	txts, err := r.LookupTXT(ctx, domain)
	if err != nil {
		return ""
	}
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=spf1") {
			return txt
		}
	}
	return ""
}

func lookupDMARC(ctx context.Context, r *net.Resolver, domain string) string {
	txts, err := r.LookupTXT(ctx, "_dmarc."+domain)
	if err != nil {
		return ""
	}
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=DMARC1") {
			return txt
		}
	}
	return ""
}

func lookupDKIM(ctx context.Context, r *net.Resolver, domain string) (string, bool) {
	for _, sel := range dkimSelectors {
		query := fmt.Sprintf("%s._domainkey.%s", sel, domain)
		txts, err := r.LookupTXT(ctx, query)
		if err != nil {
			continue
		}
		for _, txt := range txts {
			if strings.Contains(txt, "v=DKIM1") || strings.Contains(txt, "k=rsa") || strings.Contains(txt, "p=") {
				return sel, true
			}
		}
	}
	return "", false
}

// trunc shortens a string to n characters, appending "…" if truncated.
func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
