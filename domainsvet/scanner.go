package main

import "time"

// RunChecks orchestrates all domain vetting checks and returns a scored report.
func RunChecks(cfg Config) Report {
	report := Report{
		Domain:    cfg.Domain,
		Timestamp: time.Now().UTC(),
	}

	// DNS health checks (A, MX, SPF, DMARC, DKIM)
	report.DNS = CheckDNS(cfg.Domain, cfg.Timeout)

	// Blacklist checks — pass resolved IPs from DNS to avoid a second lookup
	report.Blacklists = CheckBlacklists(cfg.Domain, report.DNS.ARecords, cfg.Timeout)

	// SSL certificate validity, age, and expiry
	report.SSL = CheckSSL(cfg.Domain, cfg.Timeout)

	// Domain registration age via WHOIS protocol
	report.Age = CheckAge(cfg.Domain, cfg.Timeout)

	// Optional: VirusTotal reputation
	if cfg.VTKey != "" {
		report.VT = CheckVirusTotal(cfg.Domain, cfg.VTKey, cfg.Timeout)
	}

	// Optional: Google Safe Browsing
	if cfg.GSBKey != "" {
		report.GSB = CheckSafeBrowsing(cfg.Domain, cfg.GSBKey, cfg.Timeout)
	}

	// Tally scores
	report.TotalScore = report.DNS.Score + report.Blacklists.Score +
		report.SSL.Score + report.Age.Score
	report.MaxScore = report.DNS.MaxScore + report.Blacklists.MaxScore +
		report.SSL.MaxScore + report.Age.MaxScore

	if report.VT != nil {
		report.TotalScore += report.VT.Score
		report.MaxScore += report.VT.MaxScore
	}
	if report.GSB != nil {
		report.TotalScore += report.GSB.Score
		report.MaxScore += report.GSB.MaxScore
	}

	if report.MaxScore > 0 {
		report.Percentage = float64(report.TotalScore) / float64(report.MaxScore) * 100
	}

	report.Verdict = calcVerdict(report.Percentage)
	return report
}

func calcVerdict(pct float64) string {
	switch {
	case pct >= 85:
		return "READY"
	case pct >= 70:
		return "LIKELY READY"
	case pct >= 50:
		return "CAUTION"
	default:
		return "NOT READY"
	}
}
