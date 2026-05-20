// hl7-security-tester: bidirectional HL7 security assessment tool.
// Tests for eavesdropping, replay attacks, and denial of service vulnerabilities.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hl7-security-tester/pkg/editor"
	"github.com/hl7-security-tester/pkg/hl7"
	"github.com/hl7-security-tester/pkg/reporter"
	"github.com/hl7-security-tester/pkg/security"
	"github.com/hl7-security-tester/pkg/transport"
)

const banner = `
╔══════════════════════════════════════════════════════════════════════╗
║          HL7 SECURITY TESTER  —  HIPAA / PHI Assessment Tool        ║
║  Tests: Eavesdropping · Replay Attacks · Denial of Service          ║
╚══════════════════════════════════════════════════════════════════════╝
`

func main() {
	// ── Flags ───────────────────────────────────────────────────────────
	host := flag.String("host", "localhost", "Target HL7 receiver hostname or IP")
	port := flag.Int("port", 2575, "Target HL7 receiver port")
	msgFile := flag.String("file", "", "Path to file containing HL7 messages (one per MSH block, or pipe-delimited)")
	useTLS     := flag.Bool("tls", false, "Use TLS with full certificate verification (uses system roots unless -ca is provided)")
	tlsAuto    := flag.Bool("tls-auto", false, "Use TLS with no certificates required. Connects and encrypts automatically,\n\t\t\taccepting whatever certificate the server presents. No -ca, -cert, or -key needed.")
	certFile   := flag.String("cert", "", "Client certificate (PEM) for mutual TLS — only needed when the SERVER requires\n\t\t\tclient authentication. Not required for -tls-auto in most cases.")
	keyFile    := flag.String("key", "", "Client key (PEM) for mutual TLS — pair with -cert when server requires client auth")
	caFile     := flag.String("ca", "", "CA certificate (PEM) to verify the server's cert. When used with -tls-auto,\n\t\t\tenables full chain validation instead of accept-any-cert.")
	skipVerify := flag.Bool("skip-verify", false, "Skip TLS certificate verification (INSECURE — used internally by TLS tests)")

	// MSH identity — the receiver uses these to decide whether to accept the message.
	// If you get "Authentication failed" errors, set these to match what the server expects.
	// Ask the receiving system administrator for the exact values.
	sendingApp      := flag.String("msh-sending-app",      "", "MSH-3: your sending application name (e.g. MYSYSTEM)")
	sendingFacility := flag.String("msh-sending-facility", "", "MSH-4: your sending facility name   (e.g. MYHOSP)")
	receivingApp    := flag.String("msh-receiving-app",    "", "MSH-5: target application name      (e.g. RHAPSODY)")
	recvFacility    := flag.String("msh-receiving-facility","","MSH-6: target facility name         (e.g. DESTHOSP)")

	// Pre-auth: some servers send a challenge on connect before accepting MLLP.
	// Set this to the exact string the server expects as a response.
	preAuth := flag.String("pre-auth", "", "String to send immediately after connect, before any HL7.\n\t\t\tUse when the server requires a login/token challenge before MLLP.")

	// Sanitize flags — automatically fix common issues before sending
	sanitize     := flag.Bool("sanitize", false, "Automatically fix common ACK-blocking issues before sending:\n\t\t\t• Fills missing MSH-7 (timestamp), MSH-10 (message ID), MSH-12 (version)\n\t\t\t• Removes SFT/UAC segments (not universally supported)\n\t\t\t• Removes empty FT1 segments\n\t\t\t• Fills missing PID-3 (MRN) and PID-5 (patient name) with defaults\n\t\t\t• Ensures OBX-11 result status is present\n\t\t\tUse this when sending captured messages that are getting no ACK.")
	sanitizeMRN  := flag.String("sanitize-mrn",  "TEST001",          "Default MRN to use when PID-3 is empty (used with -sanitize)")
	sanitizeName := flag.String("sanitize-name", "TESTPATIENT^TEST", "Default patient name when PID-5 is empty (used with -sanitize)")
	sanitizeVer  := flag.String("sanitize-version", "",              "HL7 version to fill into empty MSH-12 (default: auto-detect or 2.5)")

	timeout     := flag.Duration("timeout", 10*time.Second, "Connection timeout")
	ackTimeout  := flag.Duration("ack-timeout", 60*time.Second, "How long to wait for an ACK from the receiver (default: 60s).\n\t\t\tAccepts any Go duration: -ack-timeout 30s  -ack-timeout 2m  -ack-timeout 120s")
	readTimeout := flag.Duration("read-timeout", 0, "Alias for -ack-timeout (both work identically)")
	noResponse  := flag.Bool("no-response", false, "Do not wait for an ACK after sending.\n\t\t\tUse when the receiver accepts messages but never sends an ACK back.\n\t\t\tThe message is sent and the tool moves on immediately.")
	outputFmt := flag.String("output", "text", "Output format: text|json")
	outputFile := flag.String("out-file", "", "Write report to file (default: stdout)")
	debug := flag.Bool("debug", false, "Enable debug/verbose logging")
	interactive := flag.Bool("interactive", false, "Launch interactive shell mode")
	editMode    := flag.Bool("edit", false, "Launch the message editor to add/modify/paste HL7 segments")
	probeOnly   := flag.Bool("probe", false, "Send a minimal ADT^A01 probe message and verify ACK AA before anything else.\n\t\t\tUse this first to confirm the receiver is accepting messages correctly.\n\t\t\tDiagnoses connection, MLLP, ACK code, and MSH identity issues.")
	skipProbe   := flag.Bool("skip-probe", false, "Skip the automatic ACK probe that runs before security tests.")

	// Fuzzer flags
	fuzzFile     := flag.String("fuzz", "", "Load captured HL7 from this file and auto-fuzz fields while sending.\n\t\t\tCombine with -fuzz-iter, -fuzz-strategy, -fuzz-seg, -fuzz-out etc.")
	fuzzIter     := flag.Int("fuzz-iter", 100, "Number of fuzz iterations (default: 100)")
	fuzzDelay    := flag.Int("fuzz-delay", 100, "Milliseconds between fuzz sends (default: 100)")
	fuzzStrategy := flag.String("fuzz-strategy", "all", "Fuzz strategies: boundary,injection,format,random,overflow,encoding,all")
	fuzzSeg      := flag.String("fuzz-seg", "", "Only fuzz this segment type (e.g. PID, OBX). Empty = all segments.")
	fuzzField    := flag.Int("fuzz-field", 0, "Only fuzz this field number. 0 = all fields.")
	fuzzOut      := flag.String("fuzz-out", "", "Save fuzz results to this CSV file")
	fuzzCrash    := flag.Bool("fuzz-stop-on-crash", false, "Stop fuzzing if server stops responding")

	// Tagging — marks tool messages in receiver logs so they are distinguishable
	// from real device messages without touching any clinical data fields.
	fuzzTag      := flag.String("fuzz-tag", "SECTEST",
		"Prefix embedded in every fuzz message ID (MSH-10).\n\t\t\t"+
		"Receiver logs show e.g. SECTEST000042 vs real device IDs.\n\t\t\t"+
		"Default: SECTEST")
	fuzzSendApp  := flag.String("fuzz-sending-app", "",
		"Override MSH-3 on all fuzz messages to tag them in receiver logs.\n\t\t\t"+
		"Example: -fuzz-sending-app HL7SECTEST\n\t\t\t"+
		"Receiver sees HL7SECTEST vs real device app name — instantly distinguishable.")
	fuzzSendFac  := flag.String("fuzz-sending-facility", "",
		"Override MSH-4 (sending facility) on all fuzz messages.\n\t\t\t"+
		"Use with -fuzz-sending-app for complete tagging.")
	skipTLSTests := flag.Bool("skip-tls-tests", false, "Skip TLS version/cipher tests (use when target is plain TCP)")
	floodConns := flag.Int("flood-conns", 50, "Number of connections for flood test")
	floodConc := flag.Int("flood-concurrency", 10, "Concurrency for flood test")
	slowHold := flag.Duration("slow-hold", 10*time.Second, "Duration to hold idle connection in slow-client test")
	oversizeMB  := flag.Int("oversize-mb", 10, "Size in MB for the oversized message DoS test (default: 10).\n\t\t\tIncrease to stress-test buffer limits: -oversize-mb 50  -oversize-mb 100")
	runTests := flag.String("tests", "all", "Comma-separated tests to run: all|encryption|tls|cert|replay|timestamp|flood|oversize|malformed|slow|phi")

	flag.Usage = usage
	flag.Parse()

	fmt.Print(banner)

	// ── Load messages ────────────────────────────────────────────────────
	var messages []string
	if *msgFile != "" {
		var err error
		messages, err = loadMessages(*msgFile)
		if err != nil {
			fatalf("loading messages from %q: %v", *msgFile, err)
		}
		logf(*debug, "[INIT] Loaded %d HL7 message(s) from %s", len(messages), *msgFile)

		// Auto-sanitize if requested — fixes common ACK-blocking issues
		if *sanitize {
			fmt.Printf("  Sanitizing %d message(s) for maximum ACK compatibility...\n", len(messages))
			opts := editor.DefaultSanitizeOptions()
			opts.DefaultMRN          = *sanitizeMRN
			opts.DefaultPatientName  = *sanitizeName
			if *sanitizeVer != "" {
				opts.DefaultVersion = *sanitizeVer
			}
			opts.SendingApp        = *sendingApp
			opts.SendingFacility   = *sendingFacility
			opts.ReceivingApp      = *receivingApp
			opts.ReceivingFacility = *recvFacility
			var results []editor.SanitizeResult
			messages, results = editor.SanitizeAll(messages, opts)
			editor.PrintSanitizeReport(results)
			fmt.Println()
		}

		for i, m := range messages {
			parsed, err := hl7.Parse(m)
			if err != nil {
				logf(*debug, "[WARN] Message %d parse error: %v", i+1, err)
				continue
			}
			fmt.Printf("  [MSG %d] %s\n", i+1, parsed.SummaryString())
		}
		fmt.Println()
	}

	// ── Transport config ─────────────────────────────────────────────────
	// Validate: -tls and -tls-auto are mutually exclusive
	if *useTLS && *tlsAuto {
		fatalf("-tls and -tls-auto are mutually exclusive. Use -tls-auto to connect without certs, -tls for full verification.")
	}

	// Warn if user passed -cert/-key with -tls-auto but no server likely requires it
	if *tlsAuto && (*certFile != "" || *keyFile != "") {
		fmt.Println("  NOTE: -tls-auto was specified with -cert/-key.")
		fmt.Println("        Client certificates are only needed when the SERVER requires mutual TLS (mTLS).")
		fmt.Println("        If the server did not ask for a client cert, you can drop -cert and -key.")
		fmt.Println()
	}
	if *tlsAuto && *certFile != "" && *keyFile == "" {
		fatalf("-cert provided without -key. Both are required for client certificate authentication.")
	}
	if *tlsAuto && *keyFile != "" && *certFile == "" {
		fatalf("-key provided without -cert. Both are required for client certificate authentication.")
	}

	// -ack-timeout takes priority; fall back to -read-timeout for backward compat
	effectiveACKTimeout := *ackTimeout
	if *readTimeout != 60*time.Second {
		// user explicitly set -read-timeout, honour it
		effectiveACKTimeout = *readTimeout
	}

	cfg := transport.Config{
		Host:              *host,
		Port:              *port,
		UseTLS:            *useTLS,
		TLSAuto:           *tlsAuto,
		CertFile:          *certFile,
		KeyFile:           *keyFile,
		CAFile:            *caFile,
		SkipVerify:        *skipVerify,
		Timeout:           *timeout,
		ReadTimeout:       effectiveACKTimeout,
		NoResponse:        *noResponse,
		SendingApp:        *sendingApp,
		SendingFacility:   *sendingFacility,
		ReceivingApp:      *receivingApp,
		ReceivingFacility: *recvFacility,
		PreAuthString:     *preAuth,
	}

	// ── Probe-only mode ─────────────────────────────────────────────────────
	if *probeOnly {
		result := transport.ProbeACK(cfg)
		result.Print()
		if result.Passed {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	// ── Fuzz mode ────────────────────────────────────────────────────────────
	if *fuzzFile != "" {
		fuzzCfg := editor.FuzzConfig{
			TargetFile:      *fuzzFile,
			Host:            *host,
			Port:            *port,
			TLSAuto:         *tlsAuto || *useTLS,
			SkipVerify:      *skipVerify || *tlsAuto,
			Iterations:      *fuzzIter,
			DelayMs:         *fuzzDelay,
			Strategies:      strings.Split(*fuzzStrategy, ","),
			SegmentFilter:   *fuzzSeg,
			FieldFilter:     *fuzzField,
			OutputFile:      *fuzzOut,
			StopOnCrash:     *fuzzCrash,
			Tag:             *fuzzTag,
			SendingApp:      *fuzzSendApp,
			SendingFacility: *fuzzSendFac,
		}
		logFn := func(format string, args ...interface{}) {
			if *debug {
				fmt.Printf("[DBG] "+format+"\n", args...)
			}
		}
		session, err := editor.NewFuzzSession(fuzzCfg, logFn)
		if err != nil {
			fatalf("Fuzz session error: %v", err)
		}
		fmt.Printf("  Loaded %d message(s) from %s\n", session.MessageCount(), *fuzzFile)
		session.Run()
		return
	}

	// ── Editor mode ───────────────────────────────────────────────────────────
	if *editMode {
		ed := editor.New(*msgFile, messages)
		ed.Run()
		messages = ed.Messages
		fmt.Printf("\n  Editor closed. %d message(s) in memory.\n", len(messages))
		fmt.Println("  Re-run with -file pointing to your saved file to use them in tests.")
		return
	}

	// ── Interactive mode ─────────────────────────────────────────────────
	if *interactive {
		runInteractive(cfg, messages, *debug)
		return
	}

	// ── Run security tests ───────────────────────────────────────────────
	target := fmt.Sprintf("%s:%d", *host, *port)
	rep := &reporter.Report{
		Target:    target,
		StartTime: time.Now(),
	}

	logFn := func(format string, args ...interface{}) {
		if *debug {
			fmt.Printf(format+"\n", args...)
		}
	}

	runner := security.NewRunner(cfg, messages, *debug, logFn)
	runner.MaxMsgSizeMB = *oversizeMB
	testSet := parseTestSet(*runTests)

	tlsMode := "none (plaintext)"
	if *useTLS {
		tlsMode = "verified"
	} else if *tlsAuto {
		tlsMode = "auto (accept-any-cert)"
	}
	fmt.Printf("  Target : %s  (TLS=%s)\n", target, tlsMode)
	fmt.Printf("  Tests  : %s\n\n", *runTests)

	// Probe connectivity first
	fmt.Print("  Checking connectivity... ")
	probeClient, probeErr := transport.Dial(cfg)
	if probeErr != nil {
		fmt.Printf("FAILED\n  Error: %v\n\n", probeErr)
		fmt.Println("  Note: Some tests will still run (e.g. plaintext check).")
	} else {
		rep.TLSInfo = probeClient.Info
		probeClient.Close()
		if cfg.UseTLS || cfg.TLSAuto {
			mode := "verified"
			if cfg.TLSAuto {
				mode = "auto/accept-any-cert"
			}
			fmt.Printf("OK (TLS %s, cipher=%s, mode=%s)\n\n",
				rep.TLSInfo.TLSVersion, rep.TLSInfo.CipherSuite, mode)
		} else {
			fmt.Printf("OK (plaintext TCP)\n\n")
		}
	}

	// ── ACK Probe — verify receiver accepts a basic message before testing ─
	if !*skipProbe {
		fmt.Println("  Running ACK probe (send -skip-probe to bypass)...")
		probeResult := transport.ProbeACK(cfg)
		if probeResult.Passed {
			fmt.Printf("  ✓ Probe passed — receiver ACK'd in %s. Proceeding with tests.\n\n",
				probeResult.Duration.Round(time.Millisecond))
		} else {
			probeResult.Print()
			fmt.Println("  ⚠  Probe failed. Security tests may not produce reliable results.")
			fmt.Println("     Fix the issues above first, or run with -skip-probe to test anyway.")
			fmt.Println()
			// Ask user if they want to continue
			fmt.Print("  Continue with security tests anyway? (y/N) ")
			var answer string
			fmt.Scanln(&answer)
			if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "y") {
				fmt.Println("  Exiting. Fix the probe issues then re-run.")
				os.Exit(1)
			}
			fmt.Println()
		}
	}

	// ── Run selected tests ───────────────────────────────────────────────

	if testSet["encryption"] {
		fmt.Println("  Running: Encryption / Eavesdropping tests...")
		rep.Add(runner.TestEncryptionRequired())
		rep.Add(runner.TestPHIExposureInResponse())
	}

	if testSet["tls"] && !*skipTLSTests {
		fmt.Println("  Running: TLS version tests...")
		for _, f := range runner.TestTLSVersion() {
			rep.Add(f)
		}
	}

	if testSet["cert"] && (*useTLS || *tlsAuto) {
		fmt.Println("  Running: Certificate validation tests...")
		for _, f := range runner.TestCertificateValidity() {
			rep.Add(f)
		}
	}

	if testSet["replay"] {
		fmt.Println("  Running: Replay attack tests...")
		rep.Add(runner.TestReplayAttack())
	}

	if testSet["timestamp"] {
		fmt.Println("  Running: Timestamp replay tests...")
		rep.Add(runner.TestTimestampReplay())
	}

	if testSet["flood"] {
		fmt.Printf("  Running: Connection flood test (%d connections, concurrency=%d)...\n",
			*floodConns, *floodConc)
		rep.Add(runner.TestConnectionFlood(*floodConns, *floodConc))
	}

	if testSet["oversize"] {
		fmt.Println("  Running: Oversized message test...")
		rep.Add(runner.TestOversizedMessage())
	}

	if testSet["malformed"] {
		fmt.Println("  Running: Malformed message tests...")
		for _, f := range runner.TestMalformedMessages() {
			rep.Add(f)
		}
	}

	if testSet["slow"] {
		fmt.Printf("  Running: Slow client test (hold=%s)...\n", *slowHold)
		rep.Add(runner.TestSlowClient(*slowHold))
	}


	// ── Advanced security tests ─────────────────────────────────────────────

	if testSet["seginject"] {
		fmt.Println("  Running: Segment injection tests (Black Hat 2018 / ERNW 2020 attack vectors)...")
		for _, f := range runner.TestSegmentInjection() {
			rep.Add(f)
		}
	}

	if testSet["tampering"] {
		fmt.Println("  Running: Field tampering / data integrity tests...")
		for _, f := range runner.TestFieldTampering() {
			rep.Add(f)
		}
	}

	if testSet["injection"] {
		fmt.Println("  Running: SQL / command / script injection tests...")
		for _, f := range runner.TestInjectionAttacks() {
			rep.Add(f)
		}
	}

	if testSet["spoof"] {
		fmt.Println("  Running: Unauthorized sender / spoofing tests...")
		for _, f := range runner.TestUnauthorizedSender() {
			rep.Add(f)
		}
	}

	if testSet["enum"] {
		fmt.Println("  Running: Patient record enumeration tests...")
		for _, f := range runner.TestPatientEnumeration() {
			rep.Add(f)
		}
	}

	if testSet["errleakage"] {
		fmt.Println("  Running: Error message information leakage tests...")
		for _, f := range runner.TestErrorMessageLeakage() {
			rep.Add(f)
		}
	}

	if testSet["audit"] {
		fmt.Println("  Running: Audit trail weakness tests...")
		for _, f := range runner.TestAuditTrailWeakness() {
			rep.Add(f)
		}
	}

	if testSet["nackleak"] {
		fmt.Println("  Running: NACK PHI leakage tests...")
		for _, f := range runner.TestNACKPHILeakage() {
			rep.Add(f)
		}
	}

	rep.EndTime = time.Now()
	fmt.Println()

	// ── Output report ────────────────────────────────────────────────────
	out := os.Stdout
	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			fatalf("creating output file: %v", err)
		}
		defer f.Close()
		out = f
		defer fmt.Printf("  Report written to: %s\n", *outputFile)
	}

	switch *outputFmt {
	case "json":
		if err := rep.PrintJSON(out); err != nil {
			fatalf("writing JSON report: %v", err)
		}
	default:
		rep.PrintText(out)
	}

	// Exit code reflects findings
	if rep.Failed > 0 {
		os.Exit(1)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// INTERACTIVE MODE
// ─────────────────────────────────────────────────────────────────────────────

func runInteractive(cfg transport.Config, messages []string, debug bool) {
	fmt.Printf(`
  Interactive Mode — commands:
    send <n>          Send message #n from loaded file
    send-raw <file>   Send raw content of a file as HL7
    parse <n>         Parse and display message #n
    connect           Open a persistent connection
    disconnect        Close connection
    replay            Run replay attack test
    flood <n>         Run connection flood with n connections
    phi               Scan loaded messages for PHI
    list              List loaded messages
    help              Show this help
    quit              Exit

`)

	var (
		client *transport.Client
		reader = bufio.NewReader(os.Stdin)
	)

	logFn := func(format string, args ...interface{}) {
		if debug {
			fmt.Printf("[DBG] "+format+"\n", args...)
		}
	}
	runner := security.NewRunner(cfg, messages, debug, logFn)

	for {
		fmt.Printf("hl7sec> ")
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := parts[0]
		args := parts[1:]

		switch cmd {
		case "quit", "exit", "q":
			if client != nil {
				client.Close()
			}
			fmt.Println("Bye.")
			return

		case "help":
			fmt.Println(`  send <n>        Send message #n (1-based)
  send-raw <f>    Read file and send as HL7
  parse <n>       Show parsed fields of message #n
  connect         Open persistent connection
  disconnect      Close persistent connection
  replay          Run replay attack test
  timestamp       Run timestamp replay test
  flood <n>       Flood with n connections (default 20)
  oversize        Send 10MB message
  slow <secs>     Slow client test
  malformed       Send malformed messages
  phi             Scan messages for PHI
  list            List loaded messages
  tls             Run TLS version tests
  cert            Run certificate tests
  edit            Open message editor (add segments, paste real HL7, save)
  quit            Exit`)

		case "list":
			if len(messages) == 0 {
				fmt.Println("  No messages loaded. Use -file flag.")
			}
			for i, m := range messages {
				p, err := hl7.Parse(m)
				if err != nil {
					fmt.Printf("  [%d] (parse error: %v)\n", i+1, err)
					continue
				}
				fmt.Printf("  [%d] %s\n", i+1, p.SummaryString())
			}

		case "parse":
			idx := argInt(args, 0, 1) - 1
			if idx < 0 || idx >= len(messages) {
				fmt.Printf("  No message #%d\n", idx+1)
				continue
			}
			p, err := hl7.Parse(messages[idx])
			if err != nil {
				fmt.Printf("  Parse error: %v\n", err)
				continue
			}
			fmt.Printf("  MessageType : %s\n", p.MessageType)
			fmt.Printf("  MessageID   : %s\n", p.MessageID)
			fmt.Printf("  Timestamp   : %s\n", p.Timestamp.Format(time.RFC3339))
			fmt.Printf("  Segments    : %d\n", len(p.Segments))
			for _, seg := range p.Segments {
				fmt.Printf("    %-4s  %s\n", seg.ID, strings.Join(seg.Fields[1:], " | "))
			}
			phi := p.ContainsPHI()
			if len(phi) > 0 {
				fmt.Printf("  PHI fields  : %s\n", strings.Join(phi, ", "))
			}

		case "connect":
			if client != nil {
				fmt.Println("  Already connected. Use 'disconnect' first.")
				continue
			}
			c, err := transport.Dial(cfg)
			if err != nil {
				fmt.Printf("  Connect failed: %v\n", err)
				continue
			}
			client = c
			addr := cfg.Host + ":" + strconv.Itoa(cfg.Port)
			if c.Info.UsedTLS {
				fmt.Printf("  Connected to %s (%s %s)\n", addr, c.Info.TLSVersion, c.Info.CipherSuite)
			} else {
				fmt.Printf("  Connected to %s (plaintext)\n", addr)
			}

		case "disconnect":
			if client == nil {
				fmt.Println("  Not connected.")
				continue
			}
			client.Close()
			client = nil
			fmt.Println("  Disconnected.")

		case "send":
			idx := argInt(args, 0, 1) - 1
			if idx < 0 || idx >= len(messages) {
				fmt.Printf("  No message #%d\n", idx+1)
				continue
			}
			c, err := ensureConn(client, cfg)
			if err != nil {
				fmt.Printf("  Connection error: %v\n", err)
				continue
			}
			if client == nil {
				defer c.Close() // ephemeral
			}

			fmt.Printf("  Sending message #%d...\n", idx+1)
			respRaw, dur, err := c.Send(messages[idx])
			if err != nil {
				fmt.Printf("  Send error: %v\n", err)
				continue
			}
			respStr, framed := hl7.UnwrapMLLP(respRaw)
			fmt.Printf("  Response (%s, MLLP-framed=%v):\n", dur.Round(time.Millisecond), framed)
			printHL7Pretty(respStr)

		case "send-raw":
			if len(args) == 0 {
				fmt.Println("  Usage: send-raw <filepath>")
				continue
			}
			data, err := os.ReadFile(args[0])
			if err != nil {
				fmt.Printf("  Read error: %v\n", err)
				continue
			}
			c, err := ensureConn(client, cfg)
			if err != nil {
				fmt.Printf("  Connection error: %v\n", err)
				continue
			}
			respRaw, dur, err := c.Send(string(data))
			if err != nil {
				fmt.Printf("  Error: %v\n", err)
				continue
			}
			respStr, _ := hl7.UnwrapMLLP(respRaw)
			fmt.Printf("  Response (%s):\n", dur.Round(time.Millisecond))
			printHL7Pretty(respStr)

		case "replay":
			f := runner.TestReplayAttack()
			printFinding(f)

		case "timestamp":
			f := runner.TestTimestampReplay()
			printFinding(f)

		case "flood":
			n := argInt(args, 0, 20)
			f := runner.TestConnectionFlood(n, 5)
			printFinding(f)

		case "oversize":
			f := runner.TestOversizedMessage()
			printFinding(f)

		case "slow":
			secs := argInt(args, 0, 10)
			f := runner.TestSlowClient(time.Duration(secs) * time.Second)
			printFinding(f)

		case "malformed":
			for _, f := range runner.TestMalformedMessages() {
				printFinding(f)
			}

		case "tls":
			for _, f := range runner.TestTLSVersion() {
				printFinding(f)
			}

		case "cert":
			for _, f := range runner.TestCertificateValidity() {
				printFinding(f)
			}

		case "edit":
			ed := editor.New("", messages)
			ed.Run()
			messages = ed.Messages
			runner = security.NewRunner(cfg, messages, debug, logFn)
			fmt.Printf("  Editor closed. %d message(s) now in memory.\n", len(messages))

		case "phi":
			if len(messages) == 0 {
				fmt.Println("  No messages loaded.")
				continue
			}
			for i, m := range messages {
				p, err := hl7.Parse(m)
				if err != nil {
					continue
				}
				phi := p.ContainsPHI()
				fmt.Printf("  Message #%d (%s): %d PHI field(s)\n", i+1, p.MessageID, len(phi))
				for _, field := range phi {
					fmt.Printf("    • %s\n", field)
				}
			}

		default:
			fmt.Printf("  Unknown command: %q  (type 'help')\n", cmd)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// loadMessages reads a file and splits it into individual HL7 messages.
// Supports files where messages are separated by blank lines or MSH boundaries.
func loadMessages(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Normalize ALL line endings to \n for consistent splitting
	content := string(data)
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	// Blank-line separated (most common format)
	if strings.Contains(content, "\n\n") {
		blocks := strings.Split(content, "\n\n")
		var msgs []string
		for _, b := range blocks {
			b = strings.TrimSpace(b)
			if strings.HasPrefix(b, "MSH") {
				msgs = append(msgs, b)
			}
		}
		if len(msgs) > 0 {
			return msgs, nil
		}
	}

	// Fall back: split on MSH boundaries
	return splitByMSH(content), nil
}

func splitByMSH(content string) []string {
	// Normalize ALL line endings to \r first
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	var msgs []string
	var current strings.Builder
	for _, seg := range strings.Split(content, "\n") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		if strings.HasPrefix(seg, "MSH") && current.Len() > 0 {
			msg := strings.TrimSpace(current.String())
			if msg != "" {
				msgs = append(msgs, msg)
			}
			current.Reset()
		}
		current.WriteString(seg + "\r")
	}
	if current.Len() > 0 {
		msg := strings.TrimSpace(current.String())
		if msg != "" {
			msgs = append(msgs, msg)
		}
	}
	return msgs
}

func parseTestSet(spec string) map[string]bool {
	all := map[string]bool{
		"encryption": true,
		"tls":        true,
		"cert":       true,
		"replay":     true,
		"timestamp":  true,
		"flood":      true,
		"oversize":   true,
		"malformed":  true,
		"slow":       true,
		"phi":        true,
		// Advanced tests
		"injection":  true,
		"tampering":  true,
		"spoof":      true,
		"enum":       true,
		"errleakage": true,
		"audit":      true,
		"nackleak":   true,
		"seginject":  true,
	}
	if spec == "all" {
		return all
	}
	set := map[string]bool{}
	for _, t := range strings.Split(spec, ",") {
		set[strings.TrimSpace(t)] = true
	}
	return set
}

func ensureConn(existing *transport.Client, cfg transport.Config) (*transport.Client, error) {
	if existing != nil && existing.IsConnected() {
		return existing, nil
	}
	return transport.Dial(cfg)
}

func printHL7Pretty(raw string) {
	raw = strings.ReplaceAll(raw, "\r", "\n")
	for _, line := range strings.Split(raw, "\n") {
		if line != "" {
			fmt.Printf("    %s\n", line)
		}
	}
}

func printFinding(f security.Finding) {
	icon := "✗"
	if f.Passed {
		icon = "✓"
	}
	fmt.Printf("  %s [%-8s] %s\n", icon, f.Severity, f.TestName)
	fmt.Printf("    %s\n", f.Description)
	if f.Detail != "" {
		fmt.Printf("    Detail: %s\n", f.Detail)
	}
}

func argInt(args []string, index, defaultVal int) int {
	if index < len(args) {
		n, err := strconv.Atoi(args[index])
		if err == nil {
			return n
		}
	}
	return defaultVal
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(2)
}

func logf(debug bool, format string, args ...interface{}) {
	if debug {
		fmt.Printf("[DBG] "+format+"\n", args...)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `
HL7 Security Tester — HIPAA/PHI Security Assessment Tool

USAGE:
  hl7-security-tester [flags]

BASIC:
  -host string        Target receiver hostname/IP (default: localhost)
  -port int           Target port (default: 2575)
  -file string        HL7 message file (MSH blocks, blank-line separated)
  -tests string       Tests to run: all|encryption|tls|cert|replay|timestamp|
                      flood|oversize|malformed|slow|phi  (default: all)

SANITIZE (fix captured messages for maximum ACK compatibility):
  -sanitize             Auto-fix common ACK-blocking issues before sending:
                          • Fills missing MSH-7 (timestamp), MSH-10 (message ID), MSH-12 (version)
                          • Removes SFT/UAC segments not supported by all receivers
                          • Removes empty FT1 segments
                          • Fills missing PID-3 (MRN) and PID-5 (patient name)
                          • Ensures OBX-11 result status is present
  -sanitize-mrn string  Default MRN when PID-3 is empty (default: TEST001)
  -sanitize-name string Default patient name when PID-5 is empty
  -sanitize-version str HL7 version for empty MSH-12 (default: 2.5)

AUTHENTICATION:
  -msh-sending-app string      MSH-3: your sending application name.
  -msh-sending-facility string MSH-4: your sending facility name.
  -msh-receiving-app string    MSH-5: the target application name.
  -msh-receiving-facility str  MSH-6: the target facility name.

  If you get "Authentication failed" errors, the receiver is rejecting your
  MSH identity fields. Ask the system admin for the exact values they expect,
  then pass them with these flags. They overwrite whatever is in your .hl7 file.

  Example:
    -msh-sending-app TESTSYS -msh-sending-facility MYHOSP \
    -msh-receiving-app RHAPSODY -msh-receiving-facility DESTHOSP

  -pre-auth string             Raw string to send immediately after TCP/TLS
                               connect, before any MLLP frames. Use when the
                               server issues a login challenge on connect.

TLS:
  -tls                Use TLS with full certificate verification.
                      Uses system certificate roots unless -ca is provided.

  -tls-auto           Use TLS with zero configuration. No -ca, -cert, or -key
                      needed. Just connects and encrypts, accepting whatever
                      certificate the server presents. Use this when you want
                      to test the TLS handshake without hunting for cert files.

  -ca string          CA certificate (PEM) to verify the server. Optional with
                      -tls-auto — providing it switches from accept-any to full
                      chain validation.

  -cert string        Client certificate (PEM). Only needed when the SERVER
                      requires mutual TLS (mTLS) from connecting clients.
                      Rare — most HL7 receivers do not require this.

  -key string         Client key (PEM). Required only alongside -cert.

  -skip-verify        Disable TLS certificate verification entirely.
                      INSECURE — used internally by the TLS downgrade tests.

TIMEOUTS:
  -timeout duration     Connection timeout (default: 10s)
  -ack-timeout dur      How long to wait for an ACK from the receiver.
                        Default: 60s. Accepts any Go duration string:
                          -ack-timeout 30s
                          -ack-timeout 90s
                          -ack-timeout 2m
                          -ack-timeout 120s
  -read-timeout dur     Alias for -ack-timeout (both work identically)
  -no-response          Do not wait for an ACK at all — fire and forget.
                        Use when the receiver never sends an ACK back.
                        The message is confirmed sent; the tool moves on.

DOS TUNING:
  -flood-conns int         Connections for flood test (default: 50)
  -flood-concurrency int   Concurrency for flood test (default: 10)
  -slow-hold duration      Idle hold duration for slow-client test (default: 10s)

OUTPUT:
  -output string      Output format: text|json (default: text)
  -out-file string    Write report to file (default: stdout)
  -debug              Verbose debug logging

MODES:
  -interactive        Launch interactive shell

EXAMPLES:
  # Full assessment over TLS
  hl7-security-tester -host hl7recv.hospital.com -port 2575 \
    -tls -ca ca.pem -file messages.hl7 -debug

  # Replay + flood tests only, JSON output
  hl7-security-tester -host 10.0.0.5 -port 2575 \
    -file msgs.hl7 -tests replay,flood -output json -out-file report.json

  # Interactive shell
  hl7-security-tester -host 10.0.0.5 -port 2575 -file msgs.hl7 -interactive

`)
}
