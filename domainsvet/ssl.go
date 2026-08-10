package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// CheckSSL connects to the domain on port 443 and inspects the leaf certificate.
// Scoring: Valid(10) + Age>30d(5) + Expiry>30d(5) = 20 points max.
func CheckSSL(domain string, timeout time.Duration) SSLResult {
	result := SSLResult{MaxScore: 20}
	now := time.Now()

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", &tls.Config{
		ServerName: domain,
	})
	if err != nil {
		result.Valid = false
		result.Error = err.Error()
		result.Checks = append(result.Checks, Check{
			Name:      "SSL Certificate",
			Status:    Fail,
			Detail:    "Connection failed: " + summarizeSSLError(err.Error()),
			Points:    0,
			MaxPoints: 10,
		})
		// Pad MaxScore to 20 even on failure so scoring denominator is consistent
		return result
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		result.Valid = false
		result.Error = "no certificates in TLS chain"
		result.Checks = append(result.Checks, Check{
			Name:      "SSL Certificate",
			Status:    Fail,
			Detail:    "Empty certificate chain",
			Points:    0,
			MaxPoints: 10,
		})
		return result
	}

	cert := certs[0]
	result.Valid = true
	result.NotBefore = cert.NotBefore
	result.NotAfter = cert.NotAfter
	result.Subject = cert.Subject.CommonName
	result.AgeDays = int(now.Sub(cert.NotBefore).Hours() / 24)
	result.DaysUntilExpiry = int(cert.NotAfter.Sub(now).Hours() / 24)

	if len(cert.Issuer.Organization) > 0 {
		result.Issuer = cert.Issuer.Organization[0]
	} else {
		result.Issuer = cert.Issuer.CommonName
	}

	// ── Valid cert ───────────────────────────────────────────── 10 pts ──
	result.Checks = append(result.Checks, Check{
		Name:      "Certificate Valid",
		Status:    Pass,
		Detail:    fmt.Sprintf("Issuer: %s | Subject: %s", result.Issuer, result.Subject),
		Points:    10,
		MaxPoints: 10,
	})
	result.Score += 10

	// ── Certificate age ──────────────────────────────────────── 5 pts ──
	if result.AgeDays >= 30 {
		result.Checks = append(result.Checks, Check{
			Name:      "Certificate Age",
			Status:    Pass,
			Detail:    fmt.Sprintf("%d days old (issued %s)", result.AgeDays, cert.NotBefore.Format("2006-01-02")),
			Points:    5,
			MaxPoints: 5,
		})
		result.Score += 5
	} else {
		result.Checks = append(result.Checks, Check{
			Name:      "Certificate Age",
			Status:    Warn,
			Detail:    fmt.Sprintf("%d days old — recently issued cert is a SEG/sandbox signal", result.AgeDays),
			Points:    0,
			MaxPoints: 5,
		})
	}

	// ── Expiry ───────────────────────────────────────────────── 5 pts ──
	switch {
	case result.DaysUntilExpiry > 30:
		result.Checks = append(result.Checks, Check{
			Name:      "Certificate Expiry",
			Status:    Pass,
			Detail:    fmt.Sprintf("%d days remaining (expires %s)", result.DaysUntilExpiry, cert.NotAfter.Format("2006-01-02")),
			Points:    5,
			MaxPoints: 5,
		})
		result.Score += 5
	case result.DaysUntilExpiry > 0:
		result.Checks = append(result.Checks, Check{
			Name:      "Certificate Expiry",
			Status:    Warn,
			Detail:    fmt.Sprintf("Expires in %d days — renew before operational use", result.DaysUntilExpiry),
			Points:    2,
			MaxPoints: 5,
		})
		result.Score += 2
	default:
		result.Checks = append(result.Checks, Check{
			Name:      "Certificate Expiry",
			Status:    Fail,
			Detail:    "Certificate has expired",
			Points:    0,
			MaxPoints: 5,
		})
	}

	return result
}

func summarizeSSLError(e string) string {
	switch {
	case strings.Contains(e, "certificate has expired"):
		return "certificate expired"
	case strings.Contains(e, "certificate signed by unknown authority"):
		return "untrusted certificate authority"
	case strings.Contains(e, "connection refused"):
		return "port 443 not open"
	case strings.Contains(e, "no such host"):
		return "domain does not resolve"
	case strings.Contains(e, "i/o timeout"), strings.Contains(e, "timeout"):
		return "connection timed out"
	default:
		if len(e) > 80 {
			return e[:80] + "…"
		}
		return e
	}
}
