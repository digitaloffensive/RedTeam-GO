// probe.go — Sends a minimal valid HL7 message and verifies a clean ACK
// before any security tests run. Diagnoses exactly what is wrong if no ACK
// is received, so the user knows what to fix before wasting test iterations.
package transport

import (
	"fmt"
	"strings"
	"time"

	"github.com/hl7-security-tester/pkg/hl7"
)

// ProbeResult holds the full diagnostic outcome of an ACK probe.
type ProbeResult struct {
	// Connection
	Connected   bool
	TLSVersion  string
	CipherSuite string

	// Message send
	Sent        bool
	SentMessage string

	// Response
	GotResponse  bool
	ResponseRaw  string
	ResponseText string
	MLLPFramed   bool
	ACKCode      string // AA, AE, AR, or empty
	ErrorText    string // MSA-3 error description
	Duration     time.Duration

	// Diagnosis
	Passed      bool
	Issues      []string
	Suggestions []string
}

// ProbeACK sends the simplest possible valid HL7 message to the receiver
// and returns a full diagnostic result. This should always be the first
// thing run before any security tests or fuzzing.
//
// The probe message is a minimal ADT^A01 with:
//   - A fresh unique message ID
//   - All required MSH fields populated
//   - A minimal PID with a test MRN and name
//   - No optional segments that might confuse receivers
func ProbeACK(cfg Config) ProbeResult {
	result := ProbeResult{}

	// ── Step 1: Connect ──────────────────────────────────────────────────────
	client, err := Dial(cfg)
	if err != nil {
		result.Connected = false
		result.Issues = append(result.Issues, fmt.Sprintf("Cannot connect: %v", err))
		result.Suggestions = diagnosConnectError(err.Error(), cfg)
		return result
	}
	defer client.Close()

	result.Connected = true
	if client.Info.UsedTLS {
		result.TLSVersion = client.Info.TLSVersion
		result.CipherSuite = client.Info.CipherSuite
	}

	// ── Step 2: Build the minimal probe message ───────────────────────────────
	// Keep it as simple as possible — only what every HL7 receiver must accept.
	now := time.Now().Format("20060102150405")
	msgID := fmt.Sprintf("PROBE%d", time.Now().UnixMilli()%999999)

	sendApp := cfg.SendingApp
	if sendApp == "" {
		sendApp = "HL7PROBE"
	}
	sendFac := cfg.SendingFacility
	if sendFac == "" {
		sendFac = "PROBE"
	}
	recvApp := cfg.ReceivingApp
	if recvApp == "" {
		recvApp = "RECEIVER"
	}
	recvFac := cfg.ReceivingFacility
	if recvFac == "" {
		recvFac = "FACILITY"
	}

	probe := strings.Join([]string{
		fmt.Sprintf("MSH|^~\\&|%s|%s|%s|%s|%s||ADT^A01|%s|P|2.5",
			sendApp, sendFac, recvApp, recvFac, now, msgID),
		"EVN|A01|" + now,
		"PID|1||PROBEMRN001^^^FACILITY||PROBETEST^HL7||19800101|M",
		"PV1|1|O",
	}, "\r")

	result.SentMessage = probe

	// ── Step 3: Send and wait for ACK ────────────────────────────────────────
	probeCfg := cfg
	if probeCfg.ReadTimeout == 0 {
		probeCfg.ReadTimeout = 30 * time.Second
	}

	respRaw, dur, sendErr := client.Send(probe)
	result.Duration = dur
	result.Sent = true

	if sendErr != nil {
		result.GotResponse = false
		result.Issues = append(result.Issues, fmt.Sprintf("Send/receive error: %v", sendErr))
		result.Suggestions = diagnoseSendError(sendErr.Error(), dur)
		return result
	}

	result.GotResponse = true
	result.ResponseRaw = string(respRaw)

	// ── Step 4: Parse the response ───────────────────────────────────────────
	respStr, framed := hl7.UnwrapMLLP(respRaw)
	result.ResponseText = respStr
	result.MLLPFramed = framed
	result.ACKCode = extractACKCode(respStr)
	result.ErrorText = extractMSAText(respStr)

	// ── Step 5: Diagnose ─────────────────────────────────────────────────────
	switch result.ACKCode {
	case "AA":
		result.Passed = true

	case "AE":
		result.Passed = false
		result.Issues = append(result.Issues, "Receiver returned AE (Application Error)")
		if result.ErrorText != "" {
			result.Issues = append(result.Issues,
				fmt.Sprintf("Error text from receiver: %q", result.ErrorText))
		}
		result.Suggestions = diagnoseAE(result.ErrorText, cfg)

	case "AR":
		result.Passed = false
		result.Issues = append(result.Issues, "Receiver returned AR (Application Reject)")
		if result.ErrorText != "" {
			result.Issues = append(result.Issues,
				fmt.Sprintf("Reject reason: %q", result.ErrorText))
		}
		result.Suggestions = diagnoseAR(result.ErrorText, cfg)

	case "":
		result.Passed = false
		if len(strings.TrimSpace(respStr)) == 0 {
			result.Issues = append(result.Issues,
				"Receiver sent an empty response — no MSA segment found")
			result.Suggestions = []string{
				"The receiver accepted the TCP connection and message but sent nothing back",
				"Try -no-response flag if the receiver is known to not send ACKs",
				"Check receiver logs — it may have processed the message silently",
				"Try -ack-timeout 120s in case the receiver is very slow",
			}
		} else {
			result.Issues = append(result.Issues,
				fmt.Sprintf("Response received but no MSA/ACK code found. Raw: %q", truncate(respStr, 200)))
			result.Suggestions = []string{
				"Receiver sent a response but it does not look like a standard HL7 ACK",
				"Check if receiver uses a non-standard ACK format",
				"The response may be a pre-auth challenge — try -pre-auth flag",
			}
		}

	default:
		result.Passed = false
		result.Issues = append(result.Issues,
			fmt.Sprintf("Unexpected ACK code: %q (expected AA, AE, or AR)", result.ACKCode))
	}

	if !result.MLLPFramed && result.GotResponse {
		result.Issues = append(result.Issues,
			"Response was not MLLP-framed (missing 0x0B start byte) — receiver may be misconfigured")
	}

	return result
}

// Print writes a human-readable probe report to stdout.
func (r *ProbeResult) Print() {
	fmt.Println()
	fmt.Println("  ┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("  │  ACK PROBE — Basic connectivity and message acceptance test  │")
	fmt.Println("  └─────────────────────────────────────────────────────────────┘")
	fmt.Println()

	// Connection
	if r.Connected {
		fmt.Print("  [✓] TCP/TLS connection  ")
		if r.TLSVersion != "" {
			fmt.Printf("(%s, %s)", r.TLSVersion, r.CipherSuite)
		} else {
			fmt.Print("(plaintext)")
		}
		fmt.Println()
	} else {
		fmt.Println("  [✗] TCP/TLS connection  FAILED")
	}

	// Send
	if r.Sent {
		fmt.Println("  [✓] Message sent        (minimal ADT^A01 probe)")
	}

	// Response
	if r.GotResponse {
		frameStatus := "MLLP-framed"
		if !r.MLLPFramed {
			frameStatus = "unframed"
		}
		fmt.Printf("  [✓] Response received   (%s, %s)\n", frameStatus, r.Duration.Round(time.Millisecond))
	} else if r.Sent {
		fmt.Println("  [✗] Response            NO RESPONSE")
	}

	// ACK
	if r.ACKCode != "" {
		icon := "✗"
		if r.ACKCode == "AA" {
			icon = "✓"
		}
		fmt.Printf("  [%s] ACK code            %s", icon, r.ACKCode)
		if r.ErrorText != "" {
			fmt.Printf("  (%s)", r.ErrorText)
		}
		fmt.Println()
	}

	// Overall
	fmt.Println()
	if r.Passed {
		fmt.Println("  ✓  PROBE PASSED — Receiver is accepting messages and sending ACK AA")
		fmt.Println("     Safe to run security tests and fuzzing.")
	} else {
		fmt.Println("  ✗  PROBE FAILED — Receiver is not sending a clean ACK AA")
		fmt.Println()
		if len(r.Issues) > 0 {
			fmt.Println("  Issues found:")
			for _, issue := range r.Issues {
				fmt.Printf("    • %s\n", issue)
			}
		}
		if len(r.Suggestions) > 0 {
			fmt.Println()
			fmt.Println("  Suggested fixes:")
			for i, s := range r.Suggestions {
				fmt.Printf("    %d. %s\n", i+1, s)
			}
		}
	}

	// Always show the probe message for reference
	fmt.Println()
	fmt.Println("  Probe message sent:")
	for _, seg := range strings.Split(r.SentMessage, "\r") {
		if seg != "" {
			fmt.Printf("    %s\n", seg)
		}
	}

	if r.GotResponse && r.ResponseText != "" {
		fmt.Println()
		fmt.Println("  Receiver response:")
		for _, seg := range strings.Split(r.ResponseText, "\r") {
			seg = strings.TrimSpace(seg)
			if seg != "" {
				fmt.Printf("    %s\n", seg)
			}
		}
	}
	fmt.Println()
}

// ─────────────────────────────────────────────────────────────────────────────
// Diagnosis helpers
// ─────────────────────────────────────────────────────────────────────────────

func diagnosConnectError(errMsg string, cfg Config) []string {
	var suggestions []string
	lower := strings.ToLower(errMsg)

	if strings.Contains(lower, "refused") {
		suggestions = append(suggestions,
			fmt.Sprintf("Nothing is listening on %s:%d — verify host and port", cfg.Host, cfg.Port),
			"Check the receiver is running and not in maintenance mode",
			"Confirm there is no firewall blocking the port",
		)
	} else if strings.Contains(lower, "timeout") {
		suggestions = append(suggestions,
			"Host is reachable but not responding — possible firewall silently dropping packets",
			"Try ping and traceroute to confirm network path",
			"Increase -timeout value e.g. -timeout 30s",
		)
	} else if strings.Contains(lower, "tls") || strings.Contains(lower, "handshake") {
		suggestions = append(suggestions,
			"TLS handshake failed — try -tls-auto instead of -tls",
			"Receiver may not support TLS — try without any TLS flag",
			"Check the receiver's TLS version requirements",
		)
	} else if strings.Contains(lower, "authentication") {
		suggestions = append(suggestions,
			"Authentication failed at the TLS layer",
			"Try -tls-auto to accept any server certificate",
			"Check if the receiver requires a client certificate (-cert / -key)",
			"Ask the admin for the correct MSH sending app/facility values",
		)
	} else if strings.Contains(lower, "no such host") {
		suggestions = append(suggestions,
			fmt.Sprintf("Cannot resolve hostname %q — check the -host value", cfg.Host),
			"Try using the IP address directly instead of a hostname",
		)
	}

	if len(suggestions) == 0 {
		suggestions = append(suggestions,
			"Verify -host and -port are correct",
			"Check network connectivity to the receiver",
			"Run with -debug for more detail",
		)
	}
	return suggestions
}

func diagnoseSendError(errMsg string, dur time.Duration) []string {
	lower := strings.ToLower(errMsg)
	var suggestions []string

	if strings.Contains(lower, "timeout") {
		suggestions = append(suggestions,
			fmt.Sprintf("Timed out after %s — receiver accepted the connection but did not ACK", dur.Round(time.Second)),
			"Increase the ACK wait time: -ack-timeout 120s",
			"Try -no-response to skip waiting (verifies send works)",
			"Check receiver logs to see if the message arrived",
			"Add -sanitize flag to fix any structural issues in the message",
		)
	} else if strings.Contains(lower, "broken pipe") || strings.Contains(lower, "reset") {
		suggestions = append(suggestions,
			"Receiver closed the connection immediately after receiving the message",
			"The MSH identity fields may not match what the receiver expects",
			"Use -msh-sending-app / -msh-receiving-app flags to set correct values",
			"Add -sanitize to fix structural issues (missing version, empty segments)",
			"Try -pre-auth if the receiver requires authentication before MLLP",
		)
	} else if strings.Contains(lower, "eof") {
		suggestions = append(suggestions,
			"Receiver closed connection without sending an ACK",
			"Common causes: wrong MSH application/facility identity, missing required fields",
			"Add -sanitize to auto-fix the message before sending",
			"Use -msh-sending-app to set the sending application name the receiver expects",
		)
	}

	if len(suggestions) == 0 {
		suggestions = append(suggestions,
			"Run with -debug for detailed connection logging",
			"Check the receiver logs for the specific rejection reason",
		)
	}
	return suggestions
}

func diagnoseAE(errText string, cfg Config) []string {
	lower := strings.ToLower(errText)
	suggestions := []string{}

	if strings.Contains(lower, "unknown") || strings.Contains(lower, "unsupported") {
		suggestions = append(suggestions,
			"Message type may not be supported — the probe uses ADT^A01",
			"Check which message types the receiver accepts",
		)
	}
	if strings.Contains(lower, "version") {
		suggestions = append(suggestions,
			"HL7 version mismatch — try -sanitize-version 2.6 to match receiver",
		)
	}
	if strings.Contains(lower, "segment") {
		suggestions = append(suggestions,
			"A required segment may be missing or a segment order is wrong",
			"Use -sanitize to fix common structural issues",
		)
	}
	suggestions = append(suggestions,
		"Check receiver logs for the full error description",
		"The receiver processed the message but rejected it at the application level",
	)
	return suggestions
}

func diagnoseAR(errText string, cfg Config) []string {
	lower := strings.ToLower(errText)
	suggestions := []string{}

	if strings.Contains(lower, "auth") || strings.Contains(lower, "unknown sender") ||
		strings.Contains(lower, "access") {
		suggestions = append(suggestions,
			"Receiver is rejecting the sender identity (MSH-3/4/5/6)",
			fmt.Sprintf("Current sending app: %q — ask admin for the exact expected value", cfg.SendingApp),
			"Use -msh-sending-app and -msh-receiving-app with the correct values",
		)
	}
	if strings.Contains(lower, "duplicate") {
		suggestions = append(suggestions,
			"Duplicate message ID — the probe ID is already in the receiver's log",
			"This is unlikely for a probe but restart the receiver or wait",
		)
	}

	suggestions = append(suggestions,
		"AR means the receiver understood the message but actively rejected it",
		"Most common cause: MSH sender/receiver identity does not match receiver config",
		"Use -msh-sending-app APPNAME -msh-sending-facility FACNAME with exact values from receiver admin",
	)
	return suggestions
}

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

func extractMSAText(response string) string {
	for _, line := range strings.Split(response, "\r") {
		if strings.HasPrefix(line, "MSA|") {
			parts := strings.Split(line, "|")
			if len(parts) > 3 {
				return strings.TrimSpace(parts[3])
			}
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
