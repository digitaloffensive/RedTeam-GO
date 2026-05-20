// Package reporter formats and outputs security test findings.
package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/hl7-security-tester/pkg/security"
	"github.com/hl7-security-tester/pkg/transport"
)

// Report aggregates all findings from a test run.
type Report struct {
	Target     string
	StartTime  time.Time
	EndTime    time.Time
	TLSInfo    transport.ConnectionInfo
	Findings   []security.Finding
	TotalTests int
	Passed     int
	Failed     int
	Warnings   int
}

// Add appends one or more findings to the report.
func (rep *Report) Add(findings ...security.Finding) {
	for _, f := range findings {
		rep.Findings = append(rep.Findings, f)
		rep.TotalTests++
		switch {
		case f.Passed:
			rep.Passed++
		case f.Severity == security.Medium || f.Severity == security.Low || f.Severity == security.Info:
			rep.Warnings++
			rep.Failed++
		default:
			rep.Failed++
		}
	}
}

// PrintText writes a human-readable report to w.
func (rep *Report) PrintText(w io.Writer) {
	sep := strings.Repeat("═", 72)
	thin := strings.Repeat("─", 72)

	fmt.Fprintln(w, sep)
	fmt.Fprintln(w, "  HL7 SECURITY ASSESSMENT REPORT")
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "  Target   : %s\n", rep.Target)
	fmt.Fprintf(w, "  Start    : %s\n", rep.StartTime.Format(time.RFC3339))
	fmt.Fprintf(w, "  End      : %s\n", rep.EndTime.Format(time.RFC3339))
	fmt.Fprintf(w, "  Duration : %s\n", rep.EndTime.Sub(rep.StartTime).Round(time.Millisecond))
	if rep.TLSInfo.UsedTLS {
		fmt.Fprintf(w, "  TLS      : %s  Cipher: %s\n", rep.TLSInfo.TLSVersion, rep.TLSInfo.CipherSuite)
	} else {
		fmt.Fprintln(w, "  TLS      : NOT USED — plaintext connection")
	}
	fmt.Fprintln(w, thin)

	// Group by category
	groups := groupFindings(rep.Findings)
	for _, g := range groups {
		fmt.Fprintf(w, "\n  ▶ %s\n", g.name)
		fmt.Fprintln(w, "  "+thin[:68])
		for _, f := range g.findings {
			icon := "✗"
			if f.Passed {
				icon = "✓"
			}
			sev := fmt.Sprintf("%-8s", f.Severity)
			fmt.Fprintf(w, "  %s [%s] %-35s %s\n", icon, sev, f.TestName, f.Description)
			if f.Detail != "" {
				for _, line := range wrapText("    → "+f.Detail, 70) {
					fmt.Fprintf(w, "  %s\n", line)
				}
			}
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "  SUMMARY: %d tests  |  %d passed  |  %d failed/warnings\n",
		rep.TotalTests, rep.Passed, rep.Failed)

	// Risk summary
	critCount := rep.countBySeverity(security.Critical)
	highCount := rep.countBySeverity(security.High)
	medCount := rep.countBySeverity(security.Medium)
	fmt.Fprintf(w, "  RISK     : %d CRITICAL  %d HIGH  %d MEDIUM\n",
		critCount, highCount, medCount)
	fmt.Fprintln(w, sep)

	if critCount+highCount > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  ⚠  CRITICAL/HIGH FINDINGS REQUIRING IMMEDIATE ATTENTION:")
		fmt.Fprintln(w, "  "+thin[:68])
		for _, f := range rep.Findings {
			if !f.Passed && (f.Severity == security.Critical || f.Severity == security.High) {
				fmt.Fprintf(w, "  • [%s] %s\n", f.Severity, f.TestName)
				fmt.Fprintf(w, "    %s\n", f.Description)
				if f.Detail != "" {
					fmt.Fprintf(w, "    Detail: %s\n", f.Detail)
				}
				fmt.Fprintln(w)
			}
		}
	}
}

// PrintJSON writes the report as JSON to w.
func (rep *Report) PrintJSON(w io.Writer) error {
	out := struct {
		Target    string             `json:"target"`
		StartTime string             `json:"start_time"`
		EndTime   string             `json:"end_time"`
		Duration  string             `json:"duration"`
		TLS       interface{}        `json:"tls"`
		Summary   map[string]int     `json:"summary"`
		Findings  []security.Finding `json:"findings"`
	}{
		Target:    rep.Target,
		StartTime: rep.StartTime.Format(time.RFC3339),
		EndTime:   rep.EndTime.Format(time.RFC3339),
		Duration:  rep.EndTime.Sub(rep.StartTime).String(),
		Summary: map[string]int{
			"total":   rep.TotalTests,
			"passed":  rep.Passed,
			"failed":  rep.Failed,
			"critical": rep.countBySeverity(security.Critical),
			"high":    rep.countBySeverity(security.High),
			"medium":  rep.countBySeverity(security.Medium),
		},
		Findings: rep.Findings,
	}
	if rep.TLSInfo.UsedTLS {
		out.TLS = map[string]string{
			"version": rep.TLSInfo.TLSVersion,
			"cipher":  rep.TLSInfo.CipherSuite,
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func (rep *Report) countBySeverity(s security.Severity) int {
	count := 0
	for _, f := range rep.Findings {
		if !f.Passed && f.Severity == s {
			count++
		}
	}
	return count
}

type findingGroup struct {
	name     string
	findings []security.Finding
}

func groupFindings(findings []security.Finding) []findingGroup {
	cats := map[string]string{
		"Encryption": "Eavesdropping / Encryption",
		"TLS":        "Eavesdropping / Encryption",
		"Cert":       "Certificate Validation",
		"Replay":     "Replay Attack Detection",
		"Timestamp":  "Replay Attack Detection",
		"Connection": "Denial of Service",
		"Oversized":  "Denial of Service",
		"Slow":       "Denial of Service",
		"Malformed":  "Input Validation",
		"PHI":        "PHI Exposure",
	}

	groups := map[string][]security.Finding{}
	order := []string{}

	for _, f := range findings {
		cat := "Other"
		for prefix, catName := range cats {
			if strings.Contains(f.TestName, prefix) {
				cat = catName
				break
			}
		}
		if _, seen := groups[cat]; !seen {
			order = append(order, cat)
		}
		groups[cat] = append(groups[cat], f)
	}
	sort.Strings(order)

	var result []findingGroup
	for _, name := range order {
		result = append(result, findingGroup{name: name, findings: groups[name]})
	}
	return result
}

func wrapText(text string, width int) []string {
	if len(text) <= width {
		return []string{text}
	}
	var lines []string
	for len(text) > width {
		lines = append(lines, text[:width])
		text = "      " + text[width:]
	}
	if text != "" {
		lines = append(lines, text)
	}
	return lines
}
