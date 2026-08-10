package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

const version = "1.0.0"

func main() {
	noColor := flag.Bool("no-color", false, "Disable colored terminal output")
	jsonOut := flag.Bool("json", false, "Output results as JSON")
	vtKey := flag.String("vt-key", "", "VirusTotal API key for reputation check (optional)")
	gsbKey := flag.String("gsb-key", "", "Google Safe Browsing API key (optional)")
	timeout := flag.Duration("timeout", 10*time.Second, "Per-check network timeout")
	ver := flag.Bool("version", false, "Print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "domainsvet v%s\n", version)
		fmt.Fprintf(os.Stderr, "Domain vetting tool for red team infrastructure assessment\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  domainsvet [flags] <domain>\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  domainsvet example.com\n")
		fmt.Fprintf(os.Stderr, "  domainsvet --vt-key YOUR_KEY example.com\n")
		fmt.Fprintf(os.Stderr, "  domainsvet --json example.com | jq .verdict\n")
	}
	flag.Parse()

	if *ver {
		fmt.Printf("domainsvet v%s\n", version)
		return
	}

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	domain := normalizeDomain(flag.Arg(0))
	if domain == "" {
		fmt.Fprintln(os.Stderr, "error: invalid domain")
		os.Exit(1)
	}

	cfg := Config{
		Domain:  domain,
		VTKey:   *vtKey,
		GSBKey:  *gsbKey,
		Timeout: *timeout,
	}

	report := RunChecks(cfg)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintln(os.Stderr, "error encoding JSON:", err)
			os.Exit(1)
		}
		return
	}

	PrintReport(report, !*noColor)
}

// normalizeDomain strips scheme, path, port, and www prefix.
func normalizeDomain(input string) string {
	s := strings.ToLower(strings.TrimSpace(input))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.IndexByte(s, '/'); idx != -1 {
		s = s[:idx]
	}
	if idx := strings.IndexByte(s, ':'); idx != -1 {
		s = s[:idx]
	}
	s = strings.TrimPrefix(s, "www.")
	return s
}
