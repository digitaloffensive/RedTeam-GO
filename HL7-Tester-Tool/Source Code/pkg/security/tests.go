// Package security contains all HL7 security test implementations.
package security

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hl7-security-tester/pkg/hl7"
	"github.com/hl7-security-tester/pkg/transport"
)

// Severity levels for findings
type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"
	Pass     Severity = "PASS"
)

// Finding represents a single security test result.
type Finding struct {
	TestName    string
	Severity    Severity
	Passed      bool
	Description string
	Detail      string
	Duration    time.Duration
	Timestamp   time.Time
}

func (f Finding) String() string {
	status := "✗ FAIL"
	if f.Passed {
		status = "✓ PASS"
	}
	return fmt.Sprintf("[%s] %-12s %-40s %s", status, f.Severity, f.TestName, f.Description)
}

// Runner executes all security tests.
type Runner struct {
	cfg          transport.Config
	messages     []string
	debug        bool
	logf         func(string, ...interface{})
	MaxMsgSizeMB int // oversized message test size in MB (default 10)
}

// NewRunner creates a new security test runner.
func NewRunner(cfg transport.Config, messages []string, debug bool, logf func(string, ...interface{})) *Runner {
	return &Runner{cfg: cfg, messages: messages, debug: debug, logf: logf, MaxMsgSizeMB: 10}
}

// -------------------------------------------------------------------
// 1. EAVESDROPPING / ENCRYPTION TESTS
// -------------------------------------------------------------------

// TestEncryptionRequired verifies the receiver requires TLS and rejects plaintext.
func (r *Runner) TestEncryptionRequired() Finding {
	f := Finding{
		TestName:  "EncryptionRequired",
		Timestamp: time.Now(),
	}

	// Try plaintext connection even if TLS is configured
	plainCfg := r.cfg
	plainCfg.UseTLS = false

	client, err := transport.Dial(plainCfg)
	if err != nil {
		// Connection refused on plaintext → server correctly requires TLS
		f.Passed = true
		f.Severity = Pass
		f.Description = "Server refuses plaintext connections"
		f.Detail = fmt.Sprintf("TCP connect rejected: %v", err)
		return f
	}
	defer client.Close()

	// Connection accepted — try sending an HL7 message
	if len(r.messages) > 0 {
		_, _, sendErr := client.Send(r.messages[0])
		if sendErr == nil {
			f.Passed = false
			f.Severity = Critical
			f.Description = "Server accepts UNENCRYPTED HL7 messages — PHI exposed to eavesdropping"
			f.Detail = "Plaintext TCP connection accepted and HL7 message delivered successfully"
			return f
		}
	}

	f.Passed = false
	f.Severity = Critical
	f.Description = "Server accepted plaintext TCP connection (TLS not enforced)"
	f.Detail = "Plaintext TCP connection was established; HL7 traffic may be readable on the network"
	return f
}

// TestTLSVersion verifies the server only accepts TLS 1.2+ and rejects deprecated versions.
func (r *Runner) TestTLSVersion() []Finding {
	var findings []Finding

	type versionTest struct {
		name    string
		version uint16
		wantFail bool
		severity Severity
	}

	tests := []versionTest{
		{"TLS1.0-Rejected", tls.VersionTLS10, true, High},
		{"TLS1.1-Rejected", tls.VersionTLS11, true, High},
		{"TLS1.2-Accepted", tls.VersionTLS12, false, Pass},
		{"TLS1.3-Accepted", tls.VersionTLS13, false, Pass},
	}

	for _, tt := range tests {
		f := Finding{TestName: tt.name, Timestamp: time.Now()}

		tlsCfg := &tls.Config{
			InsecureSkipVerify: r.cfg.SkipVerify, //nolint:gosec
			ServerName:         r.cfg.Host,
			MinVersion:         tt.version,
			MaxVersion:         tt.version,
		}

		addr := fmt.Sprintf("%s:%d", r.cfg.Host, r.cfg.Port)
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 5 * time.Second},
			"tcp", addr, tlsCfg,
		)

		connected := err == nil
		if conn != nil {
			conn.Close()
		}

		if tt.wantFail {
			if connected {
				f.Passed = false
				f.Severity = tt.severity
				f.Description = fmt.Sprintf("Server accepted deprecated %s — vulnerable to downgrade attacks", tt.name)
				f.Detail = "Deprecated TLS version negotiated successfully"
			} else {
				f.Passed = true
				f.Severity = Pass
				f.Description = fmt.Sprintf("Server correctly rejects %s", tt.name)
				f.Detail = fmt.Sprintf("Handshake error: %v", err)
			}
		} else {
			if connected {
				f.Passed = true
				f.Severity = Pass
				f.Description = fmt.Sprintf("Server supports modern %s", tt.name)
			} else {
				f.Passed = false
				f.Severity = Medium
				f.Description = fmt.Sprintf("Server does not support %s", tt.name)
				f.Detail = fmt.Sprintf("Error: %v", err)
			}
		}
		findings = append(findings, f)
	}
	return findings
}

// TestCertificateValidity inspects the server TLS certificate.
func (r *Runner) TestCertificateValidity() []Finding {
	var findings []Finding

	if !r.cfg.UseTLS {
		return []Finding{{
			TestName:    "CertificateValidity",
			Severity:    Info,
			Passed:      false,
			Description: "TLS not enabled — certificate tests skipped",
			Timestamp:   time.Now(),
		}}
	}

	client, err := transport.Dial(r.cfg)
	if err != nil {
		return []Finding{{
			TestName:    "CertificateValidity",
			Severity:    High,
			Passed:      false,
			Description: "Could not connect to perform certificate inspection",
			Detail:      err.Error(),
			Timestamp:   time.Now(),
		}}
	}
	defer client.Close()

	now := time.Now()

	for i, cert := range client.Info.PeerCerts {
		prefix := fmt.Sprintf("Cert[%d]", i)

		// Expiry
		expF := Finding{TestName: prefix + "-Expiry", Timestamp: now}
		if now.After(cert.NotAfter) {
			expF.Passed = false
			expF.Severity = Critical
			expF.Description = "Certificate is EXPIRED"
			expF.Detail = fmt.Sprintf("Expired: %s (%.0f days ago)",
				cert.NotAfter.Format(time.RFC3339),
				now.Sub(cert.NotAfter).Hours()/24)
		} else if cert.NotAfter.Sub(now) < 30*24*time.Hour {
			expF.Passed = false
			expF.Severity = High
			expF.Description = "Certificate expires within 30 days"
			expF.Detail = fmt.Sprintf("Expires: %s", cert.NotAfter.Format(time.RFC3339))
		} else {
			expF.Passed = true
			expF.Severity = Pass
			expF.Description = fmt.Sprintf("Certificate valid until %s", cert.NotAfter.Format("2006-01-02"))
		}
		findings = append(findings, expF)

		// Hostname match
		hostF := Finding{TestName: prefix + "-Hostname", Timestamp: now}
		if err := cert.VerifyHostname(r.cfg.Host); err != nil {
			hostF.Passed = false
			hostF.Severity = High
			hostF.Description = fmt.Sprintf("Certificate hostname mismatch for %s", r.cfg.Host)
			hostF.Detail = err.Error()
		} else {
			hostF.Passed = true
			hostF.Severity = Pass
			hostF.Description = fmt.Sprintf("Certificate matches hostname %s", r.cfg.Host)
		}
		findings = append(findings, hostF)

		// Key usage
		kuF := Finding{TestName: prefix + "-KeyUsage", Timestamp: now}
		if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
			kuF.Passed = true
			kuF.Severity = Pass
			kuF.Description = "Certificate has correct DigitalSignature key usage"
		} else {
			kuF.Passed = false
			kuF.Severity = Medium
			kuF.Description = "Certificate missing DigitalSignature key usage"
		}
		findings = append(findings, kuF)
	}

	// Log cipher suite used
	findings = append(findings, Finding{
		TestName:    "TLSNegotiation",
		Severity:    Info,
		Passed:      true,
		Description: fmt.Sprintf("TLS %s, cipher: %s", client.Info.TLSVersion, client.Info.CipherSuite),
		Timestamp:   now,
	})

	return findings
}

// -------------------------------------------------------------------
// 2. REPLAY ATTACK TESTS
// -------------------------------------------------------------------

// TestReplayAttack sends the same HL7 message twice and checks if the second is rejected.
func (r *Runner) TestReplayAttack() Finding {
	f := Finding{TestName: "ReplayAttack", Timestamp: time.Now()}

	if len(r.messages) == 0 {
		f.Severity = Info
		f.Description = "No messages available for replay test"
		return f
	}

	msg := r.messages[0]
	original, err := hl7.Parse(msg)
	if err != nil {
		f.Passed = false
		f.Severity = Info
		f.Description = "Could not parse message for replay test"
		f.Detail = err.Error()
		return f
	}

	r.logf("[REPLAY] Sending original message (ID=%s)...", original.MessageID)

	// First send
	client1, err := transport.Dial(r.cfg)
	if err != nil {
		f.Severity = Info
		f.Description = "Connection failed for replay test"
		f.Detail = err.Error()
		return f
	}
	resp1Raw, dur1, err := client1.Send(msg)
	client1.Close()
	if err != nil {
		f.Severity = Info
		f.Description = "First send failed — cannot test replay"
		f.Detail = err.Error()
		return f
	}

	resp1Str, _ := hl7.UnwrapMLLP(resp1Raw)
	r.logf("[REPLAY] First response (%s): %s", dur1.Round(time.Millisecond), summarizeACK(resp1Str))

	// Wait a moment then replay identical message
	time.Sleep(500 * time.Millisecond)
	r.logf("[REPLAY] Re-sending IDENTICAL message (replay)...")

	client2, err := transport.Dial(r.cfg)
	if err != nil {
		f.Severity = Info
		f.Description = "Could not reconnect for replay"
		f.Detail = err.Error()
		return f
	}
	resp2Raw, dur2, err := client2.Send(msg)
	client2.Close()

	if err != nil {
		// Connection dropped on replay — could be good
		f.Passed = true
		f.Severity = Pass
		f.Description = "Server dropped connection on replayed message"
		f.Detail = fmt.Sprintf("Error on replay: %v", err)
		return f
	}

	resp2Str, _ := hl7.UnwrapMLLP(resp2Raw)
	r.logf("[REPLAY] Replay response (%s): %s", dur2.Round(time.Millisecond), summarizeACK(resp2Str))

	// Check ACK codes
	ackCode1 := extractACKCode(resp1Str)
	ackCode2 := extractACKCode(resp2Str)

	if ackCode2 == "AE" || ackCode2 == "AR" {
		f.Passed = true
		f.Severity = Pass
		f.Description = "Server rejected replayed message (duplicate detection working)"
		f.Detail = fmt.Sprintf("First ACK=%s, Replay ACK=%s", ackCode1, ackCode2)
	} else if ackCode2 == "AA" {
		f.Passed = false
		f.Severity = High
		f.Description = "Server ACCEPTED replayed message — no duplicate/replay detection"
		f.Detail = fmt.Sprintf(
			"Identical message (ID=%s) accepted twice. First ACK=%s, Replay ACK=%s. "+
				"Attacker could re-send captured orders, admissions, or lab results.",
			original.MessageID, ackCode1, ackCode2)
	} else {
		f.Passed = false
		f.Severity = Medium
		f.Description = "Inconclusive replay test — unexpected ACK code"
		f.Detail = fmt.Sprintf("Replay ACK=%q (expected AA/AE/AR)", ackCode2)
	}
	return f
}

// TestTimestampReplay sends a message with an old timestamp (>24h) and checks rejection.
func (r *Runner) TestTimestampReplay() Finding {
	f := Finding{TestName: "TimestampReplay", Timestamp: time.Now()}

	if len(r.messages) == 0 {
		f.Severity = Info
		f.Description = "No messages for timestamp replay test"
		return f
	}

	// Modify MSH timestamp to 48 hours ago
	oldTS := time.Now().Add(-48 * time.Hour).Format("20060102150405")
	modified := rewriteMSHField(r.messages[0], 7, oldTS)

	r.logf("[TIMESTAMP-REPLAY] Sending message with 48-hour-old timestamp...")

	client, err := transport.Dial(r.cfg)
	if err != nil {
		f.Severity = Info
		f.Description = "Connection failed"
		f.Detail = err.Error()
		return f
	}
	defer client.Close()

	respRaw, dur, err := client.Send(modified)
	r.logf("[TIMESTAMP-REPLAY] Response time: %s", dur.Round(time.Millisecond))
	if err != nil {
		f.Passed = true
		f.Severity = Pass
		f.Description = "Server rejected stale-timestamp message (connection dropped)"
		return f
	}

	respStr, _ := hl7.UnwrapMLLP(respRaw)
	ackCode := extractACKCode(respStr)

	if ackCode == "AE" || ackCode == "AR" {
		f.Passed = true
		f.Severity = Pass
		f.Description = "Server rejected message with stale timestamp (48h old)"
		f.Detail = fmt.Sprintf("ACK=%s", ackCode)
	} else {
		f.Passed = false
		f.Severity = High
		f.Description = "Server accepted message with 48-hour-old timestamp"
		f.Detail = fmt.Sprintf("ACK=%s — No timestamp validation detected. Replay window is unlimited.", ackCode)
	}
	return f
}

// -------------------------------------------------------------------
// 3. DENIAL OF SERVICE TESTS
// -------------------------------------------------------------------

// TestConnectionFlood tests how the server handles many rapid connections.
func (r *Runner) TestConnectionFlood(numConns int, concurrency int) Finding {
	f := Finding{TestName: "ConnectionFlood", Timestamp: time.Now()}
	r.logf("[DOS] Connection flood: %d connections, concurrency=%d", numConns, concurrency)

	var (
		success int64
		failed  int64
		wg      sync.WaitGroup
		sem     = make(chan struct{}, concurrency)
	)

	start := time.Now()
	for i := 0; i < numConns; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			client, err := transport.Dial(transport.Config{
				Host:    r.cfg.Host,
				Port:    r.cfg.Port,
				UseTLS:  r.cfg.UseTLS,
				Timeout: 3 * time.Second,
			})
			if err != nil {
				atomic.AddInt64(&failed, 1)
				return
			}
			atomic.AddInt64(&success, 1)
			time.Sleep(100 * time.Millisecond)
			client.Close()
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	successCount := atomic.LoadInt64(&success)
	failedCount := atomic.LoadInt64(&failed)
	rate := float64(successCount) / elapsed.Seconds()

	f.Detail = fmt.Sprintf(
		"Established=%d, Refused=%d, Rate=%.1f conn/s, Duration=%s",
		successCount, failedCount, rate, elapsed.Round(time.Millisecond))

	if failedCount == 0 {
		f.Passed = false
		f.Severity = High
		f.Description = fmt.Sprintf("Server accepted all %d flood connections — no rate limiting detected", numConns)
	} else if float64(failedCount)/float64(numConns) > 0.5 {
		f.Passed = true
		f.Severity = Pass
		f.Description = fmt.Sprintf("Server rate-limited connections (%.0f%% refused)", 100*float64(failedCount)/float64(numConns))
	} else {
		f.Passed = false
		f.Severity = Medium
		f.Description = fmt.Sprintf("Server accepted %.0f%% of flood connections — weak rate limiting",
			100*float64(successCount)/float64(numConns))
	}
	return f
}

// TestOversizedMessage sends an enormous message to probe for buffer overflow/DoS.
func (r *Runner) TestOversizedMessage() Finding {
	f := Finding{TestName: "OversizedMessage", Timestamp: time.Now()}

	// Build an oversized message by padding NTE (notes) segments
	sizeMB := r.MaxMsgSizeMB
	if sizeMB <= 0 {
		sizeMB = 10
	}
	targetSize := sizeMB * 1024 * 1024
	var sb strings.Builder
	sb.WriteString("MSH|^~\\&|TEST|TEST|RECV|RECV|20240101120000||ADT^A01|HUGE001|P|2.5\r")
	sb.WriteString("PID|1||HUGE001^^^MRN||TESTPATIENT^OVERSIZED\r")
	for sb.Len() < targetSize {
		line := fmt.Sprintf("NTE|1|L|%s\r", strings.Repeat("A", 1000))
		sb.WriteString(line)
	}

	bigMsg := sb.String()
	r.logf("[DOS] Sending oversized message (%.1f MB)...", float64(len(bigMsg))/1024/1024)

	client, err := transport.Dial(r.cfg)
	if err != nil {
		f.Severity = Info
		f.Description = "Connection failed for oversized test"
		f.Detail = err.Error()
		return f
	}
	defer client.Close()

	start := time.Now()
	respRaw, _, sendErr := client.Send(bigMsg)
	elapsed := time.Since(start)

	if sendErr != nil {
		f.Passed = true
		f.Severity = Pass
		f.Description = "Server closed connection on oversized message"
		f.Detail = fmt.Sprintf("Error after %s: %v", elapsed.Round(time.Millisecond), sendErr)
		return f
	}

	respStr, _ := hl7.UnwrapMLLP(respRaw)
	ackCode := extractACKCode(respStr)

	if ackCode == "AE" || ackCode == "AR" {
		f.Passed = true
		f.Severity = Pass
		f.Description = "Server rejected oversized message with error ACK"
		f.Detail = fmt.Sprintf("ACK=%s, size=%.1f MB", ackCode, float64(len(bigMsg))/1024/1024)
	} else {
		f.Passed = false
		f.Severity = High
		f.Description = fmt.Sprintf("Server processed a %.0f MB message without error — no size limits enforced", float64(sizeMB))
		f.Detail = fmt.Sprintf("ACK=%s, size=%.1f MB, elapsed=%s", ackCode, float64(len(bigMsg))/1024/1024, elapsed.Round(time.Millisecond))
	}
	return f
}

// TestMalformedMessages sends structurally invalid HL7 to test input validation.
func (r *Runner) TestMalformedMessages() []Finding {
	var findings []Finding

	cases := []struct {
		name    string
		payload string
		desc    string
	}{
		{
			"MalformedMSH-NoFieldSep",
			"MSHinvalid no field separators at all\r",
			"No field separator",
		},
		{
			"MalformedMSH-TruncatedHeader",
			"MSH|\r",
			"Truncated MSH with only field sep",
		},
		{
			"MalformedMSH-NullBytes",
			"MSH|^~\\&|TEST|TEST|RECV|RECV|20240101|\x00\x00\x00|ADT^A01|NULL001|P|2.5\r",
			"Null bytes in message",
		},
		{
			"MalformedMSH-ExtremelyLongSegmentID",
			"MSH|^~\\&|TEST|TEST|RECV|RECV|20240101||ADT^A01|LONG001|P|2.5\r" +
				strings.Repeat("X", 65535) + "|field\r",
			"64K segment ID",
		},
		{
			"MalformedMSH-InvalidVersion",
			"MSH|^~\\&|TEST|TEST|RECV|RECV|20240101||ADT^A01|VER001|P|99.9\r",
			"Invalid HL7 version 99.9",
		},
		{
			"EmptyMessage",
			"",
			"Empty payload",
		},
		{
			"RandomGarbage",
			string(randomBytes(512)),
			"512 random bytes",
		},
	}

	for _, tc := range cases {
		f := Finding{TestName: tc.name, Timestamp: time.Now()}
		r.logf("[MALFORMED] Sending: %s...", tc.desc)

		client, err := transport.Dial(r.cfg)
		if err != nil {
			f.Severity = Info
			f.Description = "Connection failed: " + tc.desc
			f.Detail = err.Error()
			findings = append(findings, f)
			continue
		}

		var respRaw []byte
		var sendErr error
		if tc.payload == "" {
			respRaw, sendErr = client.SendRaw([]byte{hl7.MLLPStartBlock, hl7.MLLPEndBlock, hl7.MLLPCarriageRet})
		} else {
			respRaw, _, sendErr = client.Send(tc.payload)
		}
		client.Close()

		if sendErr != nil {
			f.Passed = true
			f.Severity = Pass
			f.Description = fmt.Sprintf("Server closed connection on malformed input: %s", tc.desc)
			f.Detail = fmt.Sprintf("Error: %v", sendErr)
		} else {
			respStr, _ := hl7.UnwrapMLLP(respRaw)
			ackCode := extractACKCode(respStr)
			if ackCode == "AE" || ackCode == "AR" {
				f.Passed = true
				f.Severity = Pass
				f.Description = fmt.Sprintf("Server returned error ACK for malformed input: %s", tc.desc)
				f.Detail = fmt.Sprintf("ACK=%s", ackCode)
			} else {
				f.Passed = false
				f.Severity = Medium
				f.Description = fmt.Sprintf("Server accepted malformed input without error: %s", tc.desc)
				f.Detail = fmt.Sprintf("ACK=%s — unexpected acceptance", ackCode)
			}
		}
		findings = append(findings, f)
	}
	return findings
}

// TestSlowClient holds a connection open without sending data (slowloris-style).
func (r *Runner) TestSlowClient(holdDuration time.Duration) Finding {
	f := Finding{TestName: "SlowClient", Timestamp: time.Now()}
	r.logf("[DOS] Slow client test: holding connection for %s without data...", holdDuration)

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", r.cfg.Host, r.cfg.Port),
		5*time.Second)
	if err != nil {
		f.Severity = Info
		f.Description = "Could not connect for slow client test"
		f.Detail = err.Error()
		return f
	}
	defer conn.Close()

	// Send MLLP start byte only — then wait
	_, _ = conn.Write([]byte{hl7.MLLPStartBlock})

	timer := time.NewTimer(holdDuration)
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		conn.SetReadDeadline(time.Now().Add(holdDuration + 2*time.Second)) //nolint:errcheck
		_, _ = conn.Read(buf)
		close(done)
	}()

	select {
	case <-timer.C:
		// Still connected after hold duration
		f.Passed = false
		f.Severity = Medium
		f.Description = fmt.Sprintf("Server allowed idle connection for >%s — no inactivity timeout", holdDuration)
		f.Detail = "Consider configuring a TCP/application-level idle timeout"
	case <-done:
		f.Passed = true
		f.Severity = Pass
		f.Description = fmt.Sprintf("Server closed idle connection within %s", holdDuration)
	}
	return f
}

// TestPHIExposureInResponse checks if ACK responses accidentally echo PHI.
func (r *Runner) TestPHIExposureInResponse() Finding {
	f := Finding{TestName: "PHIInACK", Timestamp: time.Now()}

	if len(r.messages) == 0 {
		f.Severity = Info
		f.Description = "No messages to test PHI exposure"
		return f
	}

	original, err := hl7.Parse(r.messages[0])
	if err != nil {
		f.Severity = Info
		f.Description = "Could not parse message"
		f.Detail = err.Error()
		return f
	}

	// Extract PHI to look for in response
	phi := original.ContainsPHI()
	r.logf("[PHI] Message contains %d PHI fields", len(phi))

	client, err := transport.Dial(r.cfg)
	if err != nil {
		f.Severity = Info
		f.Description = "Connection failed"
		f.Detail = err.Error()
		return f
	}
	defer client.Close()

	respRaw, _, sendErr := client.Send(r.messages[0])
	if sendErr != nil {
		f.Severity = Info
		f.Description = "Send failed during PHI test"
		f.Detail = sendErr.Error()
		return f
	}

	respStr, _ := hl7.UnwrapMLLP(respRaw)

	// Check if any PID name/DOB appears in ACK
	var leaked []string
	pid := original.GetSegment("PID")
	if pid != nil {
		checks := []struct{ label, value string }{
			{"PatientName", pid.Field(5)},
			{"PatientID", pid.Field(3)},
			{"DOB", pid.Field(7)},
			{"SSN", pid.Field(19)},
		}
		for _, c := range checks {
			if c.value != "" && len(c.value) > 3 && strings.Contains(respStr, c.value) {
				leaked = append(leaked, c.label+"="+c.value)
			}
		}
	}

	if len(leaked) > 0 {
		f.Passed = false
		f.Severity = High
		f.Description = "ACK response echoes patient PHI fields"
		f.Detail = fmt.Sprintf("Leaked fields: %s", strings.Join(leaked, ", "))
	} else {
		f.Passed = true
		f.Severity = Pass
		f.Description = "ACK response does not appear to echo PHI"
	}
	return f
}

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

func extractACKCode(response string) string {
	for _, line := range strings.Split(response, "\r") {
		if strings.HasPrefix(line, "MSA|") {
			parts := strings.Split(line, "|")
			if len(parts) > 1 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func summarizeACK(response string) string {
	code := extractACKCode(response)
	if code == "" {
		return fmt.Sprintf("(no ACK parsed, len=%d)", len(response))
	}
	return fmt.Sprintf("ACK code=%s", code)
}

// rewriteMSHField returns a copy of the raw message with MSH field at 1-based index replaced.
func rewriteMSHField(raw string, fieldIndex int, newValue string) string {
	lines := strings.Split(raw, "\r")
	if len(lines) == 0 {
		return raw
	}
	if !strings.HasPrefix(lines[0], "MSH") {
		return raw
	}
	parts := strings.Split(lines[0], "|")
	if fieldIndex < len(parts) {
		parts[fieldIndex] = newValue
	}
	lines[0] = strings.Join(parts, "|")
	return strings.Join(lines, "\r")
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rand.Intn(256)) //nolint:gosec
	}
	return b
}
