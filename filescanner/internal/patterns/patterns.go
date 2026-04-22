// Package patterns defines all sensitive data detection patterns.
// To add a new pattern category, create a new Pattern entry in DefaultPatterns().
package patterns

import (
	"regexp"
)

// Match holds a single detection result within a file.
type Match struct {
	PatternName string
	LineNumber  int
	LineContent string // truncated/redacted preview
}

// Pattern represents a named sensitive data detector.
type Pattern struct {
	Name        string
	Description string
	Regex       *regexp.Regexp
	// Severity: LOW, MEDIUM, HIGH, CRITICAL
	Severity string
}

// DefaultPatterns returns the built-in set of sensitive data patterns.
func DefaultPatterns() []Pattern {
	defs := []struct {
		name     string
		desc     string
		regex    string
		severity string
	}{
		// Credentials & Secrets
		{"Password in Config", "Plain-text password assignment", `(?i)(password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{6,}`, "CRITICAL"},
		{"API Key", "Generic API key or token", `(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]?[A-Za-z0-9\-_]{16,}`, "CRITICAL"},
		{"AWS Access Key", "Amazon Web Services access key", `AKIA[0-9A-Z]{16}`, "CRITICAL"},
		{"AWS Secret Key", "Amazon Web Services secret key", `(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}`, "CRITICAL"},
		{"Private Key Block", "PEM private key header", `-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`, "CRITICAL"},
		{"Generic Secret", "Variable named 'secret' with a value", `(?i)(secret|token|auth[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9\-_]{8,}`, "HIGH"},
		{"Connection String", "Database connection string", `(?i)(Server|Data Source|Initial Catalog|mongodb(\+srv)?|redis|amqp)://[^\s'"]+`, "HIGH"},
		{"JDBC URL", "Java database connection URL", `(?i)jdbc:[a-z]+://[^\s'"]+`, "HIGH"},

		// Personal Identifiable Information (PII)
		{"SSN", "US Social Security Number", `\b\d{3}-\d{2}-\d{4}\b`, "CRITICAL"},
		{"Credit Card", "Credit card number (major networks)", `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b`, "CRITICAL"},
		{"Email Address", "Email address", `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`, "MEDIUM"},
		{"Phone Number", "US/International phone number", `\b(\+?1[-.\s]?)?(\(?\d{3}\)?[-.\s]?)(\d{3}[-.\s]?\d{4})\b`, "LOW"},
		{"IP Address", "IPv4 address (private ranges included)", `\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`, "LOW"},
		{"Date of Birth", "Date of birth label with value", `(?i)(dob|date.of.birth|birth.?date)\s*[:=]\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}`, "HIGH"},
		{"Passport Number", "Passport number pattern", `(?i)passport\s*(no|number|num|#)?\s*[:=]?\s*[A-Z]{1,2}[0-9]{6,9}`, "CRITICAL"},
		{"National ID", "National/government ID number", `(?i)(national.?id|nin|nino|national.?insurance)\s*[:=]\s*[A-Z0-9]{6,12}`, "HIGH"},

		// Financial
		{"IBAN", "International Bank Account Number", `\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b`, "HIGH"},
		{"BIC/SWIFT", "Bank Identifier Code", `\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?\b`, "MEDIUM"},
		{"Bitcoin Address", "Bitcoin wallet address", `\b(1|3|bc1)[A-HJ-NP-Za-km-z1-9]{25,62}\b`, "MEDIUM"},

		// Healthcare
		{"NHS Number", "UK National Health Service number", `\b\d{3}\s?\d{3}\s?\d{4}\b`, "HIGH"},
		{"ICD Code", "Medical diagnosis ICD code reference", `(?i)(diagnosis|icd.?10?|icd.?code)\s*[:=]\s*[A-Z]\d{2}(\.\d{1,4})?`, "MEDIUM"},
		{"HIPAA Keywords", "Healthcare-related sensitive terms", `(?i)\b(patient.?id|medical.?record|mrn|dob|diagnosis|prescription|medication|health.?record)\b`, "MEDIUM"},

		// Infrastructure
		{"Private IP Range", "RFC-1918 private IP in config", `(?i)(host|server|endpoint|url)\s*[:=]\s*['"]?(10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)`, "MEDIUM"},
		{"Internal Hostname", "Hostname ending with .local or .internal", `(?i)\b[a-z0-9\-]+\.(local|internal|corp|lan|intranet)\b`, "LOW"},
		{"Docker Secret", "Docker/k8s secret reference", `(?i)(DOCKER_PASSWORD|KUBE_TOKEN|K8S_SECRET|REGISTRY_PASSWORD)\s*[:=]\s*\S+`, "HIGH"},

		// Certificates & Keys
		{"Certificate Block", "PEM certificate block", `-----BEGIN CERTIFICATE-----`, "MEDIUM"},
		{"SSH Host Key", "SSH known_hosts or host key", `(?i)(ssh-rsa|ecdsa-sha2|ssh-ed25519)\s+[A-Za-z0-9+/=]{40,}`, "HIGH"},
	}

	out := make([]Pattern, 0, len(defs))
	for _, d := range defs {
		re, err := regexp.Compile(d.regex)
		if err != nil {
			continue
		}
		out = append(out, Pattern{
			Name:        d.name,
			Description: d.desc,
			Regex:       re,
			Severity:    d.severity,
		})
	}
	return out
}
