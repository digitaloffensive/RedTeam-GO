package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

// whoisDateFormats lists the date patterns found across common WHOIS servers.
var whoisDateFormats = []string{
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05.000Z",
	"2006-01-02T15:04:05.999999999Z07:00",
	"2006-01-02",
	"02-Jan-2006",
	"January 2, 2006",
	"2006-01-02 15:04:05",
	"2006-01-02 15:04:05 MST",
	"02/01/2006",
	"2006.01.02",
	"20060102",
}

// whoisCreationFields are field name prefixes that contain the creation date.
var whoisCreationFields = []string{
	"creation date",
	"created",
	"created on",
	"domain registration date",
	"registered",
	"registration time",
	"registered on",
	"domain registered",
	"record created",
}

// defaultWHOISServers maps common TLDs to their WHOIS servers as a fallback
// when the IANA referral lookup fails.
var defaultWHOISServers = map[string]string{
	"com":  "whois.verisign-grs.com",
	"net":  "whois.verisign-grs.com",
	"org":  "whois.pir.org",
	"io":   "whois.nic.io",
	"co":   "whois.nic.co",
	"info": "whois.afilias.net",
	"biz":  "whois.biz",
	"us":   "whois.nic.us",
	"uk":   "whois.nic.uk",
	"ca":   "whois.cira.ca",
	"au":   "whois.auda.org.au",
	"de":   "whois.denic.de",
	"fr":   "whois.nic.fr",
	"nl":   "whois.domain-registry.nl",
	"eu":   "whois.eu",
}

// CheckAge retrieves the domain registration date via the WHOIS protocol (TCP/43).
// Scoring: age-based, 0–20 points.
func CheckAge(domain string, timeout time.Duration) AgeResult {
	result := AgeResult{MaxScore: 20}

	registered, registrar, err := queryWHOIS(domain, timeout)
	if err != nil {
		result.Found = false
		result.Error = err.Error()
		result.Checks = append(result.Checks, Check{
			Name:      "Domain Age",
			Status:    Warn,
			Detail:    "WHOIS lookup failed — verify age manually at your registrar",
			Points:    0,
			MaxPoints: 20,
		})
		return result
	}

	if registered.IsZero() {
		result.Found = false
		result.Error = "creation date not found in WHOIS response"
		result.Checks = append(result.Checks, Check{
			Name:      "Domain Age",
			Status:    Warn,
			Detail:    "Could not parse registration date — WHOIS format may be non-standard",
			Points:    0,
			MaxPoints: 20,
		})
		return result
	}

	result.Found = true
	result.Registered = registered
	result.Registrar = registrar
	result.AgeDays = int(time.Since(registered).Hours() / 24)

	ageStr := formatAge(result.AgeDays)

	var pts int
	var status Status
	var detail string

	switch {
	case result.AgeDays >= 730: // 2+ years — Tier 1 candidate
		pts, status = 20, Pass
		detail = fmt.Sprintf("%s old (registered %s) — strong trust signal", ageStr, registered.Format("2006-01-02"))
	case result.AgeDays >= 365: // 1–2 years
		pts, status = 15, Pass
		detail = fmt.Sprintf("%s old (registered %s) — good for most engagements", ageStr, registered.Format("2006-01-02"))
	case result.AgeDays >= 180: // 6–12 months
		pts, status = 10, Warn
		detail = fmt.Sprintf("%s old — consider aging further before high-value ops", ageStr)
	case result.AgeDays >= 90: // 3–6 months
		pts, status = 5, Warn
		detail = fmt.Sprintf("%s old — Tier 2 candidate, not yet Tier 1", ageStr)
	case result.AgeDays >= 30: // 1–3 months
		pts, status = 2, Fail
		detail = fmt.Sprintf("%s old — too young; continue reputation seeding", ageStr)
	default: // < 30 days
		pts, status = 0, Fail
		detail = fmt.Sprintf("%s old — DO NOT USE: triggers new-registration detections", ageStr)
	}

	result.Score = pts
	result.Checks = append(result.Checks, Check{
		Name:      "Domain Age",
		Status:    status,
		Detail:    detail,
		Points:    pts,
		MaxPoints: 20,
	})

	if registrar != "" {
		result.Checks = append(result.Checks, Check{
			Name:   "Registrar",
			Status: Info,
			Detail: registrar,
		})
	}

	return result
}

// queryWHOIS resolves the correct WHOIS server via IANA and fetches the record.
func queryWHOIS(domain string, timeout time.Duration) (time.Time, string, error) {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return time.Time{}, "", fmt.Errorf("invalid domain: %s", domain)
	}
	tld := parts[len(parts)-1]

	// Step 1: ask IANA for the authoritative WHOIS server
	ianaResp, err := rawWHOISQuery("whois.iana.org", tld, timeout)
	server := ""
	if err == nil {
		server = extractWHOISField(ianaResp, "whois")
	}

	// Fallback to built-in map if IANA lookup fails
	if server == "" {
		var ok bool
		server, ok = defaultWHOISServers[strings.ToLower(tld)]
		if !ok {
			return time.Time{}, "", fmt.Errorf("no WHOIS server known for .%s", tld)
		}
	}

	// Step 2: query the authoritative server for the full domain
	resp, err := rawWHOISQuery(server, domain, timeout)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("WHOIS query to %s failed: %w", server, err)
	}

	created := parseCreationDate(resp)
	registrar := extractWHOISField(resp, "registrar")
	return created, registrar, nil
}

// rawWHOISQuery opens a TCP connection on port 43, sends the query, and returns
// the full response as a string.
func rawWHOISQuery(server, query string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", server+":43", timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}

	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", err
	}

	var sb strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// extractWHOISField returns the value of the first matching field in a WHOIS
// response (case-insensitive prefix match before the colon).
func extractWHOISField(resp, field string) string {
	for _, line := range strings.Split(resp, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		prefix := strings.ToLower(field) + ":"
		if strings.HasPrefix(lower, prefix) {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// parseCreationDate scans a WHOIS response for any known creation date field
// and returns the parsed time.
func parseCreationDate(resp string) time.Time {
	for _, line := range strings.Split(resp, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		for _, field := range whoisCreationFields {
			if strings.HasPrefix(lower, field+":") || strings.HasPrefix(lower, field+" :") {
				idx := strings.Index(trimmed, ":")
				if idx == -1 {
					continue
				}
				val := strings.TrimSpace(trimmed[idx+1:])
				// Strip inline comments
				if ci := strings.Index(val, "//"); ci != -1 {
					val = strings.TrimSpace(val[:ci])
				}
				t := tryParseDateString(val)
				if !t.IsZero() {
					return t
				}
			}
		}
	}
	return time.Time{}
}

// tryParseDateString attempts to parse a date string using known WHOIS formats.
func tryParseDateString(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, format := range whoisDateFormats {
		if t, err := time.Parse(format, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// formatAge converts a day count into a human-readable age string.
func formatAge(days int) string {
	years := days / 365
	months := (days % 365) / 30
	if years > 0 {
		return fmt.Sprintf("%d year(s) %d month(s)", years, months)
	}
	return fmt.Sprintf("%d month(s)", months)
}
