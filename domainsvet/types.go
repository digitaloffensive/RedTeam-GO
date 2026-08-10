package main

import "time"

// Config holds scanner configuration passed from CLI flags.
type Config struct {
	Domain    string
	VTKey     string
	GSBKey    string
	Timeout   time.Duration
}

// Status represents the outcome of an individual check.
type Status int

const (
	Pass Status = iota
	Warn
	Fail
	Skip
	Info
)

// Check is a single vetting check with its result and score contribution.
type Check struct {
	Name      string `json:"name"`
	Status    Status `json:"status"`
	Detail    string `json:"detail"`
	Points    int    `json:"points"`
	MaxPoints int    `json:"max_points"`
}

// DNSResult holds DNS health check results.
type DNSResult struct {
	ARecords     []string `json:"a_records"`
	MXRecords    []string `json:"mx_records"`
	SPF          string   `json:"spf"`
	DMARC        string   `json:"dmarc"`
	DKIMFound    bool     `json:"dkim_found"`
	DKIMSelector string   `json:"dkim_selector,omitempty"`
	Checks       []Check  `json:"checks"`
	Score        int      `json:"score"`
	MaxScore     int      `json:"max_score"`
}

// BlacklistEntry is the result of a single blacklist check.
type BlacklistEntry struct {
	List     string `json:"list"`
	Listed   bool   `json:"listed"`
	Response string `json:"response,omitempty"`
}

// BlacklistResult holds all blacklist check results.
type BlacklistResult struct {
	IP           string           `json:"ip"`
	IPChecks     []BlacklistEntry `json:"ip_checks"`
	DomainChecks []BlacklistEntry `json:"domain_checks"`
	TotalListed  int              `json:"total_listed"`
	Score        int              `json:"score"`
	MaxScore     int              `json:"max_score"`
}

// SSLResult holds SSL certificate check results.
type SSLResult struct {
	Valid           bool      `json:"valid"`
	Issuer          string    `json:"issuer"`
	Subject         string    `json:"subject"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	AgeDays         int       `json:"age_days"`
	DaysUntilExpiry int       `json:"days_until_expiry"`
	Error           string    `json:"error,omitempty"`
	Checks          []Check   `json:"checks"`
	Score           int       `json:"score"`
	MaxScore        int       `json:"max_score"`
}

// AgeResult holds WHOIS domain age results.
type AgeResult struct {
	Registered time.Time `json:"registered"`
	Registrar  string    `json:"registrar,omitempty"`
	AgeDays    int       `json:"age_days"`
	Found      bool      `json:"found"`
	Error      string    `json:"error,omitempty"`
	Checks     []Check   `json:"checks"`
	Score      int       `json:"score"`
	MaxScore   int       `json:"max_score"`
}

// VTResult holds VirusTotal reputation results.
type VTResult struct {
	Malicious  int     `json:"malicious"`
	Suspicious int     `json:"suspicious"`
	Harmless   int     `json:"harmless"`
	Undetected int     `json:"undetected"`
	Checks     []Check `json:"checks"`
	Score      int     `json:"score"`
	MaxScore   int     `json:"max_score"`
}

// GSBResult holds Google Safe Browsing results.
type GSBResult struct {
	Flagged     bool     `json:"flagged"`
	ThreatTypes []string `json:"threat_types,omitempty"`
	Checks      []Check  `json:"checks"`
	Score       int      `json:"score"`
	MaxScore    int      `json:"max_score"`
}

// Report is the complete vetting report for a domain.
type Report struct {
	Domain      string          `json:"domain"`
	Timestamp   time.Time       `json:"timestamp"`
	DNS         DNSResult       `json:"dns"`
	Blacklists  BlacklistResult `json:"blacklists"`
	SSL         SSLResult       `json:"ssl"`
	Age         AgeResult       `json:"age"`
	VT          *VTResult       `json:"virustotal,omitempty"`
	GSB         *GSBResult      `json:"safe_browsing,omitempty"`
	TotalScore  int             `json:"total_score"`
	MaxScore    int             `json:"max_score"`
	Percentage  float64         `json:"percentage"`
	Verdict     string          `json:"verdict"`
}
