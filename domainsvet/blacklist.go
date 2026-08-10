package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// IP-based DNS blacklists. Each entry is checked by reversing the IP and
// appending the zone (e.g., 4.3.2.1.zen.spamhaus.org).
var ipBlacklists = []struct {
	Name string
	Zone string
}{
	{"Spamhaus ZEN", "zen.spamhaus.org"},
	{"SpamCop", "bl.spamcop.net"},
	{"SORBS", "dnsbl.sorbs.net"},
	{"Barracuda", "b.barracudacentral.org"},
	{"UCEProtect L1", "dnsbl-1.uceprotect.net"},
}

// Domain-based URI blacklists. Checked by prepending the domain to the zone.
var domainBlacklists = []struct {
	Name string
	Zone string
}{
	{"Spamhaus DBL", "dbl.spamhaus.org"},
	{"SURBL", "multi.surbl.org"},
	{"URIBL Black", "black.uribl.com"},
}

// CheckBlacklists checks the domain and its primary IP against major
// DNSBL and domain blacklists.
// Scoring: 35 points — deduct 7 per listing, minimum 0.
func CheckBlacklists(domain string, aRecords []string, timeout time.Duration) BlacklistResult {
	result := BlacklistResult{MaxScore: 35}

	// Resolve IP if not provided by the DNS check
	ip := ""
	if len(aRecords) > 0 {
		ip = aRecords[0]
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupHost(ctx, domain)
		if err == nil {
			for _, a := range addrs {
				if !strings.Contains(a, ":") { // IPv4 only
					ip = a
					break
				}
			}
		}
	}
	result.IP = ip

	listedCount := 0

	// ── IP-based DNSBL checks ─────────────────────────────────────────
	if ip != "" {
		reversed := reverseIP(ip)
		if reversed != "" {
			for _, bl := range ipBlacklists {
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				entry := checkDNSBL(ctx, reversed, bl.Zone, bl.Name)
				cancel()
				result.IPChecks = append(result.IPChecks, entry)
				if entry.Listed {
					listedCount++
				}
			}
		}
	} else {
		for _, bl := range ipBlacklists {
			result.IPChecks = append(result.IPChecks, BlacklistEntry{
				List:     bl.Name,
				Listed:   false,
				Response: "skipped — no IP resolved",
			})
		}
	}

	// ── Domain-based URI blacklist checks ─────────────────────────────
	for _, bl := range domainBlacklists {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		entry := checkDomainBL(ctx, domain, bl.Zone, bl.Name)
		cancel()
		result.DomainChecks = append(result.DomainChecks, entry)
		if entry.Listed {
			listedCount++
		}
	}

	result.TotalListed = listedCount
	score := 35 - (listedCount * 7)
	if score < 0 {
		score = 0
	}
	result.Score = score

	return result
}

// reverseIP reverses an IPv4 address for DNSBL lookup.
// "1.2.3.4" → "4.3.2.1"
func reverseIP(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])
}

// checkDNSBL checks a reversed IP against a single DNSBL zone.
func checkDNSBL(ctx context.Context, reversedIP, zone, name string) BlacklistEntry {
	query := reversedIP + "." + zone
	addrs, err := net.DefaultResolver.LookupHost(ctx, query)
	if err != nil {
		return BlacklistEntry{List: name, Listed: false}
	}
	if len(addrs) > 0 {
		return BlacklistEntry{List: name, Listed: true, Response: addrs[0]}
	}
	return BlacklistEntry{List: name, Listed: false}
}

// checkDomainBL checks a domain against a domain-based URI blacklist.
func checkDomainBL(ctx context.Context, domain, zone, name string) BlacklistEntry {
	query := domain + "." + zone
	addrs, err := net.DefaultResolver.LookupHost(ctx, query)
	if err != nil {
		return BlacklistEntry{List: name, Listed: false}
	}
	if len(addrs) > 0 {
		return BlacklistEntry{List: name, Listed: true, Response: addrs[0]}
	}
	return BlacklistEntry{List: name, Listed: false}
}
