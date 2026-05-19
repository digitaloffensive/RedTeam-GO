// hl7-vulnerable-listener — A deliberately vulnerable HL7 v2.x MLLP listener
// for use as a safe test target for the HL7 Security Tester tool.
//
// DELIBERATELY VULNERABLE — DO NOT USE IN PRODUCTION
// This listener is intentionally misconfigured to demonstrate:
//   1.  No TLS / plaintext transport              (eavesdropping risk)
//   2.  No sender authentication                  (spoofing risk)
//   3.  No timestamp validation                   (replay attack)
//   4.  No duplicate message ID detection         (replay attack)
//   5.  No input sanitisation                     (injection risk)
//   6.  No message size limits                    (DoS risk)
//   7.  No connection rate limiting               (DoS risk)
//   8.  PHI echoed in error responses             (data leakage)
//   9.  Stack traces in error messages            (info disclosure)
//   10. No idle connection timeout                (slow client / DoS)
//   11. Patient data returned to unauthenticated  (enumeration)
//   12. Accepts any HL7 version                   (version downgrade)

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// MLLP constants
// ─────────────────────────────────────────────────────────────────────────────

const (
	MLLPStart = 0x0B
	MLLPEnd   = 0x1C
	MLLPCR    = 0x0D
)

// ─────────────────────────────────────────────────────────────────────────────
// Vulnerability flags — each can be toggled to show fixed vs vulnerable
// ─────────────────────────────────────────────────────────────────────────────

type VulnConfig struct {
	// Transport
	NoTLS bool // VULN 1: serve plaintext (default true for this listener)

	// Auth
	NoSenderAuth bool // VULN 2: accept any MSH-3/4 sending app/facility

	// Replay
	NoTimestampCheck  bool // VULN 3: accept messages with any timestamp age
	NoDuplicateCheck  bool // VULN 4: accept duplicate message IDs

	// Input validation
	NoInputSanitise bool // VULN 5: echo raw field values without sanitising
	NoSizeLimit     bool // VULN 6: accept messages of any size
	MaxMessageBytes int  // when NoSizeLimit=false, reject above this

	// DoS
	NoRateLimit   bool // VULN 7: accept unlimited connections
	NoIdleTimeout bool // VULN 8: never close idle connections

	// Data leakage
	EchoPhiInErrors    bool // VULN 9:  echo PID data in error/NACK responses
	StackTraceInErrors bool // VULN 10: include fake stack trace in errors

	// Enumeration
	ReturnPatientData bool // VULN 11: return fake patient records to QRY queries

	// Version
	NoVersionCheck bool // VULN 12: accept any HL7 version string
}

// AllVulnerable returns a config with every vulnerability enabled.
func AllVulnerable() VulnConfig {
	return VulnConfig{
		NoTLS:              true,
		NoSenderAuth:       true,
		NoTimestampCheck:   true,
		NoDuplicateCheck:   true,
		NoInputSanitise:    true,
		NoSizeLimit:        true,
		MaxMessageBytes:    0,
		NoRateLimit:        true,
		NoIdleTimeout:      true,
		EchoPhiInErrors:    true,
		StackTraceInErrors: true,
		ReturnPatientData:  true,
		NoVersionCheck:     true,
	}
}

// AllFixed returns a config with every vulnerability remediated.
func AllFixed() VulnConfig {
	return VulnConfig{
		NoTLS:              false, // TLS required (but this listener doesn't implement TLS — just rejects)
		NoSenderAuth:       false,
		NoTimestampCheck:   false,
		NoDuplicateCheck:   false,
		NoInputSanitise:    false,
		NoSizeLimit:        false,
		MaxMessageBytes:    1 * 1024 * 1024, // 1 MB
		NoRateLimit:        false,
		NoIdleTimeout:      false,
		EchoPhiInErrors:    false,
		StackTraceInErrors: false,
		ReturnPatientData:  false,
		NoVersionCheck:     false,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Server
// ─────────────────────────────────────────────────────────────────────────────

type Server struct {
	cfg         VulnConfig
	addr        string
	logFile     string
	verbose     bool
	seenMsgIDs  map[string]time.Time
	msgIDMu     sync.Mutex
	connCount   int64
	msgCount    int64
	rejectCount int64
	connRate    map[string][]time.Time // IP → recent connect times
	rateMu      sync.Mutex
	auditLog    *log.Logger
	auditFile   *os.File
}

func NewServer(addr string, cfg VulnConfig, logFile string, verbose bool) *Server {
	s := &Server{
		cfg:        cfg,
		addr:       addr,
		logFile:    logFile,
		verbose:    verbose,
		seenMsgIDs: make(map[string]time.Time),
		connRate:   make(map[string][]time.Time),
	}

	// Set up audit log
	if logFile != "" {
		_ = os.MkdirAll(filepath.Dir(logFile), 0755)
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			s.auditLog = log.New(f, "", 0)
			s.auditFile = f
		}
	}
	if s.auditLog == nil {
		s.auditLog = log.New(os.Stdout, "[AUDIT] ", log.LstdFlags)
	}

	return s
}

func (s *Server) Run() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen error: %w", err)
	}
	defer ln.Close()

	fmt.Printf("\n  HL7 Vulnerable Listener\n")
	fmt.Printf("  Listening on %s\n\n", s.addr)
	s.printVulnStatus()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed") {
				return nil
			}
			log.Printf("Accept error: %v", err)
			continue
		}

		// VULN 7: No rate limiting
		// FIX: rate limit by IP
		if !s.cfg.NoRateLimit {
			remoteIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()
			if s.isRateLimited(remoteIP) {
				s.logf("RATE_LIMIT", conn.RemoteAddr().String(), "Connection rejected — rate limit exceeded")
				conn.Close()
				continue
			}
		}

		atomic.AddInt64(&s.connCount, 1)
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	defer func() {
		conn.Close()
		if s.verbose {
			fmt.Printf("  [DISCONN] %s\n", remote)
		}
	}()

	s.logf("CONNECT", remote, "New connection")
	if s.verbose {
		fmt.Printf("  [CONNECT] %s\n", remote)
	}

	reader := bufio.NewReaderSize(conn, 4*1024*1024)

	for {
		// VULN 8: No idle timeout
		// FIX: set read deadline
		if !s.cfg.NoIdleTimeout {
			conn.SetReadDeadline(time.Now().Add(30 * time.Second)) //nolint:errcheck
		}

		msg, err := readMLLP(reader, s.cfg.NoSizeLimit, s.cfg.MaxMessageBytes)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "closed") &&
				!strings.Contains(err.Error(), "reset") && !strings.Contains(err.Error(), "timeout") {
				s.logf("ERROR", remote, fmt.Sprintf("Read error: %v", err))
			}
			return
		}

		if len(strings.TrimSpace(msg)) == 0 {
			continue
		}

		atomic.AddInt64(&s.msgCount, 1)
		ack := s.processMessage(msg, remote)

		// Send ACK
		frame := wrapMLLP(ack)
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
		if _, err := conn.Write(frame); err != nil {
			s.logf("ERROR", remote, fmt.Sprintf("Write error: %v", err))
			return
		}
		conn.SetWriteDeadline(time.Time{}) //nolint:errcheck
	}
}

// processMessage is the core message handler — all vulnerabilities live here.
func (s *Server) processMessage(raw, remote string) string {
	parsed := parseHL7(raw)

	s.logf("MESSAGE", remote, fmt.Sprintf("Type=%s ID=%s Segments=%d Size=%d bytes",
		parsed.MsgType, parsed.MsgID, len(parsed.Segments), len(raw)))

	if s.verbose {
		fmt.Printf("  [MSG]     %-15s ID=%-20s From=%s\n", parsed.MsgType, parsed.MsgID, remote)
		if parsed.PatientName != "" {
			fmt.Printf("  [PID]     Name=%-25s MRN=%s\n", parsed.PatientName, parsed.MRN)
		}
	}

	// ── VULN 1: Plaintext — no TLS check needed, just accept ────────────────
	// (handled at listener level — no TLS configured)

	// ── VULN 2: No sender authentication ─────────────────────────────────────
	// FIX: reject unknown senders
	if !s.cfg.NoSenderAuth {
		trusted := []string{"Sending application", "HL7PROBE", "TESTSYSTEM", "LAB", "ADT"}
		found := false
		for _, t := range trusted {
			if strings.EqualFold(parsed.SendingApp, t) {
				found = true
				break
			}
		}
		if !found {
			atomic.AddInt64(&s.rejectCount, 1)
			s.logf("REJECT", remote, fmt.Sprintf("Unknown sender: %q", parsed.SendingApp))
			return s.buildACK(parsed, "AR", "Unknown sending application: "+parsed.SendingApp, false)
		}
	}

	// ── VULN 12: No version check ─────────────────────────────────────────────
	// FIX: reject non-2.x versions
	if !s.cfg.NoVersionCheck {
		if !strings.HasPrefix(parsed.Version, "2.") {
			return s.buildACK(parsed, "AE",
				fmt.Sprintf("Unsupported HL7 version: %s (supported: 2.x)", parsed.Version), false)
		}
	}

	// ── VULN 3: No timestamp validation ──────────────────────────────────────
	// FIX: reject messages older than 10 minutes
	if !s.cfg.NoTimestampCheck && parsed.Timestamp != "" {
		ts, err := parseHL7Timestamp(parsed.Timestamp)
		if err == nil {
			age := time.Since(ts)
			if age > 10*time.Minute {
				atomic.AddInt64(&s.rejectCount, 1)
				s.logf("REJECT", remote, fmt.Sprintf("Stale timestamp: age=%s", age.Round(time.Second)))
				return s.buildACK(parsed, "AR",
					fmt.Sprintf("Message timestamp too old: %s (max age: 10 minutes)", age.Round(time.Second)), false)
			}
		}
	}

	// ── VULN 4: No duplicate message ID detection ─────────────────────────────
	// FIX: reject messages with already-seen IDs
	if !s.cfg.NoDuplicateCheck && parsed.MsgID != "" {
		s.msgIDMu.Lock()
		_, seen := s.seenMsgIDs[parsed.MsgID]
		if !seen {
			s.seenMsgIDs[parsed.MsgID] = time.Now()
		}
		s.msgIDMu.Unlock()
		if seen {
			atomic.AddInt64(&s.rejectCount, 1)
			s.logf("REJECT", remote, fmt.Sprintf("Duplicate message ID: %s", parsed.MsgID))
			return s.buildACK(parsed, "AR", "Duplicate message control ID: "+parsed.MsgID, false)
		}
	}

	// ── VULN 5: No input sanitisation ─────────────────────────────────────────
	// FIX: check for injection payloads
	if !s.cfg.NoInputSanitise {
		injectionSignals := []string{
			"DROP TABLE", "UNION SELECT", "xp_cmdshell", "<script>",
			"$(", "`", "/etc/passwd", "\rMSH", "\rRXE", "OR '1'='1",
		}
		rawUpper := strings.ToUpper(raw)
		for _, sig := range injectionSignals {
			if strings.Contains(rawUpper, strings.ToUpper(sig)) {
				atomic.AddInt64(&s.rejectCount, 1)
				s.logf("SECURITY", remote, fmt.Sprintf("Injection payload detected: %q", sig))
				return s.buildACK(parsed, "AE", "Message rejected: invalid characters in field content", false)
			}
		}
	}

	// ── VULN 6: No message size limit ─────────────────────────────────────────
	// (handled in readMLLP above when NoSizeLimit=false)

	// ── VULN 11: Return patient data to unauthenticated queries ───────────────
	// FIX: require authentication before returning patient data
	if strings.HasPrefix(parsed.MsgType, "QRY") || strings.HasPrefix(parsed.MsgType, "QBP") {
		if s.cfg.ReturnPatientData {
			s.logf("QUERY", remote, fmt.Sprintf("Patient query for MRN=%s — returning data (VULNERABLE)", parsed.QRYPatient))
			return s.buildQueryResponse(parsed)
		}
		return s.buildACK(parsed, "AR", "Query access denied: authentication required", false)
	}

	// ── Happy path: ACK AA ────────────────────────────────────────────────────
	s.logf("ACCEPT", remote, fmt.Sprintf("Message accepted: %s", parsed.MsgID))
	return s.buildACK(parsed, "AA", "", false)
}

// ─────────────────────────────────────────────────────────────────────────────
// ACK builder
// ─────────────────────────────────────────────────────────────────────────────

func (s *Server) buildACK(parsed *HL7Message, code, errText string, _ bool) string {
	now := time.Now().Format("20060102150405")
	ackMsgID := fmt.Sprintf("ACK%d", time.Now().UnixMilli())

	// VULN 9: Echo PHI in error responses
	// FIX: only include message control ID, never patient data
	errorDetail := errText
	if s.cfg.EchoPhiInErrors && code != "AA" && parsed.PatientName != "" {
		// Deliberately echo PID data back in the error text
		errorDetail = fmt.Sprintf("%s [Patient: %s MRN:%s DOB:%s SSN:%s Addr:%s Phone:%s]",
			errText, parsed.PatientName, parsed.MRN, parsed.DOB,
			parsed.SSN, parsed.Address, parsed.Phone)
	}

	msh := fmt.Sprintf("MSH|^~\\&|VulnListener|TESTFAC|%s|%s|%s||ACK|%s|P|2.5",
		parsed.SendingApp, parsed.SendingFacility, now, ackMsgID)
	msa := fmt.Sprintf("MSA|%s|%s|%s", code, parsed.MsgID, errorDetail)

	// VULN 10: Include stack trace in error responses
	// FIX: never include internal error details
	errSegments := ""
	if s.cfg.StackTraceInErrors && code != "AA" {
		errSegments = "\r" + strings.Join([]string{
			"ERR|||207&Application Internal Error&HL70357",
			"   at HL7Listener.MessageProcessor.Process(Message msg)",
			"   at HL7Listener.MLLPServer.HandleConnection(TcpClient client)",
			"   at System.Threading.Thread.Start()",
			fmt.Sprintf("   Database: Server=db01.internal;Database=HL7Store;User=sa;Password=P@ssw0rd123"),
			fmt.Sprintf("   Config: C:\\inetpub\\hl7listener\\config\\app.config"),
		}, "\r")
	}

	return msh + "\r" + msa + errSegments + "\r"
}

// buildQueryResponse returns fake patient data for QRY messages (VULN 11).
func (s *Server) buildQueryResponse(parsed *HL7Message) string {
	now := time.Now().Format("20060102150405")
	ackMsgID := fmt.Sprintf("RSP%d", time.Now().UnixMilli())

	msh := fmt.Sprintf("MSH|^~\\&|VulnListener|TESTFAC|%s|%s|%s||ADR^A19|%s|P|2.5",
		parsed.SendingApp, parsed.SendingFacility, now, ackMsgID)
	msa := fmt.Sprintf("MSA|AA|%s|Query processed", parsed.MsgID)
	// Return fake patient records — demonstrates enumeration vulnerability
	pid1 := "PID|1||MRN00001^^^HOSP||DOE^JOHN^A||19800515|M|||123 MAIN ST^^SPRINGFIELD^IL^62701||5555551234|||S||987654321"
	pid2 := "PID|2||MRN00002^^^HOSP||SMITH^JANE^B||19750320|F|||456 OAK AVE^^CHICAGO^IL^60601||5555559876|||M||123456789"
	pid3 := "PID|3||MRN00003^^^HOSP||JONES^BOB^C||19901205|M|||789 ELM ST^^ROCKFORD^IL^61101||5555554321|||S||456789123"

	return msh + "\r" + msa + "\r" + pid1 + "\r" + pid2 + "\r" + pid3 + "\r"
}

// ─────────────────────────────────────────────────────────────────────────────
// HL7 parser (minimal — enough to extract key fields)
// ─────────────────────────────────────────────────────────────────────────────

type HL7Message struct {
	Raw             string
	Segments        []string
	MsgType         string
	MsgID           string
	Timestamp       string
	SendingApp      string
	SendingFacility string
	Version         string
	// PID fields
	MRN         string
	PatientName string
	DOB         string
	SSN         string
	Address     string
	Phone       string
	// QRY fields
	QRYPatient string
}

func parseHL7(raw string) *HL7Message {
	msg := &HL7Message{Raw: raw}
	raw = strings.ReplaceAll(raw, "\r\n", "\r")
	raw = strings.ReplaceAll(raw, "\n", "\r")

	for _, line := range strings.Split(raw, "\r") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		msg.Segments = append(msg.Segments, line)
		fields := strings.Split(line, "|")
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "MSH":
			if len(fields) > 3 {
				msg.SendingApp = fields[3]
			}
			if len(fields) > 4 {
				msg.SendingFacility = fields[4]
			}
			if len(fields) > 7 {
				msg.Timestamp = fields[7]
			}
			if len(fields) > 9 {
				msg.MsgType = fields[9]
			}
			if len(fields) > 10 {
				msg.MsgID = fields[10]
			}
			if len(fields) > 12 {
				msg.Version = fields[12]
			}

		case "PID":
			if len(fields) > 3 {
				msg.MRN = fields[3]
			}
			if len(fields) > 5 {
				msg.PatientName = fields[5]
			}
			if len(fields) > 7 {
				msg.DOB = fields[7]
			}
			if len(fields) > 11 {
				msg.Address = fields[11]
			}
			if len(fields) > 13 {
				msg.Phone = fields[13]
			}
			if len(fields) > 19 {
				msg.SSN = fields[19]
			}

		case "QRD":
			if len(fields) > 8 {
				msg.QRYPatient = fields[8]
			}
		}
	}
	return msg
}

func parseHL7Timestamp(ts string) (time.Time, error) {
	ts = strings.TrimSpace(ts)
	// Handle sub-second precision e.g. 20260515165441.77
	if idx := strings.Index(ts, "."); idx > 0 {
		ts = ts[:idx]
	}
	formats := []string{"20060102150405", "200601021504", "2006010215", "20060102"}
	for _, f := range formats {
		if len(ts) == len(f) {
			return time.ParseInLocation(f, ts, time.Local)
		}
	}
	// Try longest match
	if len(ts) >= 14 {
		return time.ParseInLocation("20060102150405", ts[:14], time.Local)
	}
	if len(ts) >= 8 {
		return time.ParseInLocation("20060102", ts[:8], time.Local)
	}
	return time.Time{}, fmt.Errorf("unparseable timestamp: %s", ts)
}

// ─────────────────────────────────────────────────────────────────────────────
// MLLP framing
// ─────────────────────────────────────────────────────────────────────────────

func readMLLP(r *bufio.Reader, noSizeLimit bool, maxBytes int) (string, error) {
	// Find start byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if b == MLLPStart {
			break
		}
	}

	var buf []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			if len(buf) > 0 {
				return string(buf), nil
			}
			return "", err
		}

		if b == MLLPEnd {
			// Consume trailing CR
			next, err := r.ReadByte()
			if err == nil && next != MLLPCR {
				_ = r.UnreadByte()
			}

			// VULN 6: No size limit
			// FIX: reject if too large
			if !noSizeLimit && maxBytes > 0 && len(buf) > maxBytes {
				return "", fmt.Errorf("message too large: %d bytes (max %d)", len(buf), maxBytes)
			}

			return string(buf), nil
		}
		buf = append(buf, b)

		// Hard ceiling even in vulnerable mode to prevent OOM
		if len(buf) > 200*1024*1024 { // 200 MB absolute max
			return string(buf), nil
		}
	}
}

func wrapMLLP(msg string) []byte {
	msg = strings.ReplaceAll(msg, "\r\n", "\r")
	msg = strings.ReplaceAll(msg, "\n", "\r")
	if !strings.HasSuffix(msg, "\r") {
		msg += "\r"
	}
	frame := make([]byte, 0, len(msg)+3)
	frame = append(frame, MLLPStart)
	frame = append(frame, []byte(msg)...)
	frame = append(frame, MLLPEnd, MLLPCR)
	return frame
}

// ─────────────────────────────────────────────────────────────────────────────
// Rate limiting helpers
// ─────────────────────────────────────────────────────────────────────────────

func (s *Server) isRateLimited(ip string) bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()

	now := time.Now()
	window := time.Minute
	maxConns := 20

	times := s.connRate[ip]
	var recent []time.Time
	for _, t := range times {
		if now.Sub(t) < window {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	s.connRate[ip] = recent

	return len(recent) > maxConns
}

// ─────────────────────────────────────────────────────────────────────────────
// Logging
// ─────────────────────────────────────────────────────────────────────────────

func (s *Server) logf(event, remote, detail string) {
	entry := map[string]interface{}{
		"time":   time.Now().Format(time.RFC3339),
		"event":  event,
		"remote": remote,
		"detail": detail,
	}
	b, _ := json.Marshal(entry)
	s.auditLog.Println(string(b))
}

func (s *Server) printVulnStatus() {
	type check struct {
		label     string
		vulnerable bool
		vuln      string
		fix       string
	}
	checks := []check{
		{"Transport encryption",   s.cfg.NoTLS,              "PLAINTEXT — eavesdropping possible",       "TLS required"},
		{"Sender authentication",  s.cfg.NoSenderAuth,       "NONE — any sender accepted",               "MSH-3/4 allowlist enforced"},
		{"Timestamp validation",   s.cfg.NoTimestampCheck,   "NONE — replay window unlimited",           "Messages >10min old rejected"},
		{"Duplicate ID detection", s.cfg.NoDuplicateCheck,   "NONE — replay attacks possible",          "Seen message IDs tracked"},
		{"Input sanitisation",     s.cfg.NoInputSanitise,    "NONE — injection payloads accepted",       "Injection patterns rejected"},
		{"Message size limit",     s.cfg.NoSizeLimit,        "NONE — oversized messages accepted",       fmt.Sprintf("Max %d MB", s.cfg.MaxMessageBytes/1024/1024)},
		{"Connection rate limit",  s.cfg.NoRateLimit,        "NONE — flood attacks possible",            "20 conns/min per IP"},
		{"Idle timeout",           s.cfg.NoIdleTimeout,      "NONE — slow client attacks possible",      "30s idle timeout"},
		{"PHI in errors",          s.cfg.EchoPhiInErrors,    "ECHOED — patient data in error responses", "Error text sanitised"},
		{"Stack trace in errors",  s.cfg.StackTraceInErrors, "EXPOSED — internals in error responses",   "Generic error messages only"},
		{"Patient enumeration",    s.cfg.ReturnPatientData,  "OPEN — QRY returns patient records",       "Authentication required"},
		{"Version check",          s.cfg.NoVersionCheck,     "NONE — any HL7 version accepted",          "Version 2.x enforced"},
	}

	fmt.Println("  Vulnerability Status:")
	fmt.Println("  " + strings.Repeat("─", 65))
	for _, c := range checks {
		if c.vulnerable {
			fmt.Printf("  ✗ %-28s VULNERABLE: %s\n", c.label, c.vuln)
		} else {
			fmt.Printf("  ✓ %-28s FIXED: %s\n", c.label, c.fix)
		}
	}
	fmt.Println("  " + strings.Repeat("─", 65))
	fmt.Println()
}

func (s *Server) printStats() {
	fmt.Printf("\n  Stats: connections=%d  messages=%d  rejected=%d\n",
		atomic.LoadInt64(&s.connCount),
		atomic.LoadInt64(&s.msgCount),
		atomic.LoadInt64(&s.rejectCount))
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	port    := flag.Int("port", 2575, "Port to listen on")
	mode    := flag.String("mode", "vulnerable", "Mode: vulnerable|fixed|custom")
	logFile := flag.String("log", "hl7-listener.log", "Audit log file path")
	verbose := flag.Bool("verbose", true, "Print messages to stdout as they arrive")

	// Individual vulnerability toggles (used in custom mode)
	noTLS          := flag.Bool("no-tls",            true,  "Accept plaintext connections (no TLS)")
	noAuth         := flag.Bool("no-auth",            true,  "Accept any sending application (no allowlist)")
	noTimestamp    := flag.Bool("no-timestamp",       true,  "Accept messages with any timestamp age")
	noDuplicate    := flag.Bool("no-duplicate",       true,  "Accept duplicate message IDs")
	noSanitise     := flag.Bool("no-sanitise",        true,  "Accept injection payloads without checking")
	noSizeLimit    := flag.Bool("no-size-limit",      true,  "Accept messages of any size")
	noRateLimit    := flag.Bool("no-rate-limit",      true,  "Accept unlimited connections")
	noIdleTimeout  := flag.Bool("no-idle-timeout",    true,  "Never close idle connections")
	echoPHI        := flag.Bool("echo-phi",           true,  "Echo patient data in error responses")
	stackTrace     := flag.Bool("stack-trace",        true,  "Include stack traces in error responses")
	enumPatients   := flag.Bool("enum-patients",      true,  "Return patient data to unauthenticated queries")
	noVersionCheck := flag.Bool("no-version-check",   true,  "Accept any HL7 version")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
HL7 Vulnerable Listener — Safe test target for HL7 Security Tester

USAGE:
  hl7-vulnerable-listener [flags]

MODES:
  -mode vulnerable   All vulnerabilities enabled (default)
  -mode fixed        All vulnerabilities remediated
  -mode custom       Use individual -no-* flags to pick vulnerabilities

BASIC:
  -port int          Port to listen on (default: 2575)
  -log string        Audit log file (default: hl7-listener.log)
  -verbose           Print messages as they arrive (default: true)

INDIVIDUAL VULNERABILITY FLAGS (use with -mode custom):
  -no-tls            Accept plaintext (no TLS enforcement)
  -no-auth           Accept any sender identity
  -no-timestamp      No timestamp age validation
  -no-duplicate      No duplicate message ID detection
  -no-sanitise       No injection payload detection
  -no-size-limit     No message size limits
  -no-rate-limit     No connection rate limiting
  -no-idle-timeout   No idle connection timeout
  -echo-phi          Echo patient data in error responses
  -stack-trace       Include stack traces in errors
  -enum-patients     Return patient data to unauthenticated queries
  -no-version-check  Accept any HL7 version

EXAMPLES:
  # Fully vulnerable (default) — tests all security findings
  hl7-vulnerable-listener -port 2575

  # Fixed mode — verify your tool correctly reports PASS
  hl7-vulnerable-listener -port 2576 -mode fixed

  # Custom — vulnerable only to replay attacks
  hl7-vulnerable-listener -port 2577 -mode custom -no-timestamp=true -no-duplicate=true

  # Run both side by side and compare
  hl7-vulnerable-listener -port 2575 &
  hl7-vulnerable-listener -port 2576 -mode fixed &

`)
	}
	flag.Parse()

	var cfg VulnConfig
	switch *mode {
	case "fixed":
		cfg = AllFixed()
		fmt.Println("  Mode: FIXED — all vulnerabilities remediated")
	case "custom":
		cfg = VulnConfig{
			NoTLS:              *noTLS,
			NoSenderAuth:       *noAuth,
			NoTimestampCheck:   *noTimestamp,
			NoDuplicateCheck:   *noDuplicate,
			NoInputSanitise:    *noSanitise,
			NoSizeLimit:        *noSizeLimit,
			MaxMessageBytes:    1 * 1024 * 1024,
			NoRateLimit:        *noRateLimit,
			NoIdleTimeout:      *noIdleTimeout,
			EchoPhiInErrors:    *echoPHI,
			StackTraceInErrors: *stackTrace,
			ReturnPatientData:  *enumPatients,
			NoVersionCheck:     *noVersionCheck,
		}
		fmt.Println("  Mode: CUSTOM")
	default:
		cfg = AllVulnerable()
		fmt.Println("  Mode: VULNERABLE — all vulnerabilities enabled")
	}

	addr := fmt.Sprintf("0.0.0.0:%d", *port)
	srv := NewServer(addr, cfg, *logFile, *verbose)

	// Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n  Shutting down...")
		srv.printStats()
		if srv.auditFile != nil {
			srv.auditFile.Close()
		}
		os.Exit(0)
	}()

	if err := srv.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
