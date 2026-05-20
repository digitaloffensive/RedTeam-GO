// fuzzer.go — Loads real captured HL7 messages from a text file and
// automatically fuzzes field values while sending to the target system.
// Supports multiple fuzz strategies: boundary, injection, format, random.
package editor

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hl7-security-tester/pkg/hl7"
	"github.com/hl7-security-tester/pkg/transport"
)

// FuzzResult holds the outcome of a single fuzz attempt.
type FuzzResult struct {
	Iteration   int
	MessageID   string
	SegID       string
	FieldIndex  int
	OrigValue   string
	FuzzedValue string
	Strategy    string
	ACKCode     string
	Anomaly     string // non-empty if something interesting happened
	Duration    time.Duration
	Error       string
}

// FuzzConfig controls how the fuzzer runs.
type FuzzConfig struct {
	TargetFile   string        // path to captured HL7 file
	Host         string
	Port         int
	TLSAuto      bool
	SkipVerify   bool
	Iterations   int           // total fuzz iterations
	DelayMs      int           // ms between sends
	Strategies   []string      // boundary, injection, format, random, all
	SegmentFilter string       // only fuzz this segment type (e.g. PID), empty = all
	FieldFilter  int           // only fuzz this field index, 0 = all
	OutputFile   string        // write results CSV here
	StopOnCrash  bool          // stop if server stops responding
	Verbose      bool

	// Tagging — identifies tool messages in receiver logs without affecting clinical data.
	// Sets MSH-3 (sending app) and MSH-4 (sending facility) on every message sent.
	// The receiver sees these in its logs/monitoring alongside the real device messages.
	Tag             string // Short label embedded in MSH-10 message ID prefix e.g. "SECTEST"
	SendingApp      string // Overrides MSH-3 on all fuzz messages
	SendingFacility string // Overrides MSH-4 on all fuzz messages
}

// FuzzSession runs the fuzzing campaign.
type FuzzSession struct {
	cfg      FuzzConfig
	messages []string
	results  []FuzzResult
	logf     func(string, ...interface{})
}

// NewFuzzSession creates a fuzzer pre-loaded from a captured message file.
func NewFuzzSession(cfg FuzzConfig, logf func(string, ...interface{})) (*FuzzSession, error) {
	f := &FuzzSession{cfg: cfg, logf: logf}

	// Load messages from file
	data, err := os.ReadFile(cfg.TargetFile)
	if err != nil {
		return nil, fmt.Errorf("reading capture file: %w", err)
	}
	content := string(data)
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	if strings.Contains(content, "\n\n") {
		for _, block := range strings.Split(content, "\n\n") {
			block = strings.TrimSpace(block)
			if strings.HasPrefix(block, "MSH") {
				f.messages = append(f.messages, block)
			}
		}
	}
	if len(f.messages) == 0 {
		f.messages = splitByMSH(content)
	}
	if len(f.messages) == 0 {
		return nil, fmt.Errorf("no HL7 messages found in %s", cfg.TargetFile)
	}

	return f, nil
}

// MessageCount returns number of loaded messages.
func (fs *FuzzSession) MessageCount() int { return len(fs.messages) }

// Run executes the fuzzing campaign and prints results as it goes.
func (fs *FuzzSession) Run() []FuzzResult {
	fmt.Println()
	fmt.Printf("  ┌─────────────────────────────────────────────────────────────┐\n")
	fmt.Printf("  │  HL7 FUZZER — Loaded %d message(s) from %s\n", len(fs.messages), fs.cfg.TargetFile)
	fmt.Printf("  │  Target : %s:%d  Iterations: %d  Delay: %dms\n",
		fs.cfg.Host, fs.cfg.Port, fs.cfg.Iterations, fs.cfg.DelayMs)
	fmt.Printf("  │  Strategies: %s\n", strings.Join(fs.cfg.Strategies, ", "))
	if fs.cfg.SendingApp != "" {
		fmt.Printf("  │  Tag      : MSH-3=%s MSH-4=%s  (identifies tool in receiver logs)\n",
			fs.cfg.SendingApp, fs.cfg.SendingFacility)
	}
	if fs.cfg.Tag != "" {
		fmt.Printf("  │  Msg ID   : prefix=%s (e.g. %s000001)\n", fs.cfg.Tag, fs.cfg.Tag)
	}
	fmt.Printf("  └─────────────────────────────────────────────────────────────┘\n\n")

	strategies := resolveStrategies(fs.cfg.Strategies)
	iteration := 0
	consecutiveErrors := 0

	// Build the fuzz target list: all (seg, fieldIdx) pairs across all messages
	type fuzzTarget struct {
		msgIdx int
		segIdx int
		segID  string
		fieldIdx int
		origVal  string
	}
	var targets []fuzzTarget

	for mi, msg := range fs.messages {
		segs := splitSegments(msg)
		for si, seg := range segs {
			fields := strings.Split(seg, "|")
			if len(fields) < 2 {
				continue
			}
			segID := fields[0]
			if fs.cfg.SegmentFilter != "" && !strings.EqualFold(segID, fs.cfg.SegmentFilter) {
				continue
			}
			for fi := 1; fi < len(fields); fi++ {
				if fs.cfg.FieldFilter > 0 && fi != fs.cfg.FieldFilter {
					continue
				}
				if fields[fi] == "" || fields[fi] == "\"\"" {
					continue
				}
				// Skip MSH-1 and MSH-2 (separators — fuzzing breaks framing)
				if segID == "MSH" && (fi == 1 || fi == 2) {
					continue
				}
				targets = append(targets, fuzzTarget{
					msgIdx:   mi,
					segIdx:   si,
					segID:    segID,
					fieldIdx: fi,
					origVal:  fields[fi],
				})
			}
		}
	}

	if len(targets) == 0 {
		fmt.Println("  No fuzzable fields found with current filters.")
		return nil
	}

	fmt.Printf("  Found %d fuzzable fields across %d message(s)\n\n", len(targets), len(fs.messages))
	fmt.Printf("  %-4s %-10s %-6s %-4s %-20s %-20s %-10s %s\n",
		"#", "Strategy", "Seg", "F#", "Original", "Fuzzed", "ACK", "Anomaly")
	fmt.Println("  " + strings.Repeat("─", 90))

	connCfg := transport.Config{
		Host:       fs.cfg.Host,
		Port:       fs.cfg.Port,
		TLSAuto:    fs.cfg.TLSAuto,
		SkipVerify: fs.cfg.SkipVerify,
		Timeout:    10 * time.Second,
		ReadTimeout: 30 * time.Second,
	}

	for iteration < fs.cfg.Iterations {
		// Pick a random target and strategy
		t := targets[rand.Intn(len(targets))]           //nolint:gosec
		strategy := strategies[rand.Intn(len(strategies))] //nolint:gosec

		// Generate fuzz value
		fuzzedVal := generateFuzzValue(t.origVal, strategy)

		// Build the mutated message
		mutated := mutateField(fs.messages[t.msgIdx], t.segIdx, t.fieldIdx, fuzzedVal)

		// Assign a unique tagged message ID — visible in receiver logs
		tag := fs.cfg.Tag
		if tag == "" {
			tag = "FUZZ"
		}
		msgID := fmt.Sprintf("%s%06d", tag, iteration+1)
		mutated = rewriteMSHFields(mutated, time.Now().Format("20060102150405"), msgID)

		// Overwrite MSH-3/4 with tool identity so receiver logs show tool vs real device.
		// Skip tagging when the fuzz target IS an MSH field 3 or 4 — we would overwrite
		// the very value we are testing, producing misleading results.
		skipTag := t.segID == "MSH" && (t.fieldIdx == 3 || t.fieldIdx == 4)
		if !skipTag && (fs.cfg.SendingApp != "" || fs.cfg.SendingFacility != "") {
			mutated = tagMSHIdentity(mutated, fs.cfg.SendingApp, fs.cfg.SendingFacility)
		}

		// Send it
		result := FuzzResult{
			Iteration:   iteration + 1,
			MessageID:   msgID,
			SegID:       t.segID,
			FieldIndex:  t.fieldIdx,
			OrigValue:   t.origVal,
			FuzzedValue: fuzzedVal,
			Strategy:    strategy,
		}

		client, err := transport.Dial(connCfg)
		if err != nil {
			result.Error = fmt.Sprintf("connect failed: %v", err)
			consecutiveErrors++
			if fs.cfg.StopOnCrash && consecutiveErrors >= 3 {
				fmt.Printf("\n  ⚠ Server appears DOWN after %d consecutive connection failures — stopping.\n", consecutiveErrors)
				fmt.Printf("  Last fuzzed: %s field %d = %q\n", result.SegID, result.FieldIndex, result.FuzzedValue)
				fs.results = append(fs.results, result)
				break
			}
		} else {
			start := time.Now()
			respRaw, dur, sendErr := client.Send(mutated)
			client.Close()
			result.Duration = dur

			if sendErr != nil {
				result.Error = sendErr.Error()
				consecutiveErrors++
				if strings.Contains(sendErr.Error(), "timeout") {
					result.Anomaly = "⚠ TIMEOUT — server slow/hung"
				} else {
					result.Anomaly = "⚠ SEND ERROR"
				}
			} else {
				consecutiveErrors = 0
				respStr, _ := hl7.UnwrapMLLP(respRaw)
				result.ACKCode = extractACKCode(respStr)

				// Detect anomalies
				result.Anomaly = detectFuzzAnomaly(respStr, result.ACKCode, fuzzedVal, dur, start)
			}
		}

		// Print result line
		origTrunc := truncate(t.origVal, 18)
		fuzzTrunc := truncate(fuzzedVal, 18)
		anomalyMark := ""
		if result.Anomaly != "" {
			anomalyMark = result.Anomaly
		}
		fmt.Printf("  %-4d %-10s %-6s %-4d %-20s %-20s %-10s %s\n",
			result.Iteration,
			truncate(result.Strategy, 10),
			result.SegID,
			result.FieldIndex,
			origTrunc,
			fuzzTrunc,
			result.ACKCode,
			anomalyMark,
		)

		fs.results = append(fs.results, result)
		iteration++

		if fs.cfg.DelayMs > 0 {
			time.Sleep(time.Duration(fs.cfg.DelayMs) * time.Millisecond)
		}
	}

	fs.printSummary()
	if fs.cfg.OutputFile != "" {
		fs.saveCSV()
	}
	return fs.results
}

// ─────────────────────────────────────────────────────────────────────────────
// Fuzz value generators
// ─────────────────────────────────────────────────────────────────────────────

func generateFuzzValue(original, strategy string) string {
	switch strategy {
	case "boundary":
		return boundaryFuzz(original)
	case "injection":
		return injectionFuzz()
	case "format":
		return formatFuzz(original)
	case "random":
		return randomFuzz(original)
	case "overflow":
		return overflowFuzz(original)
	case "encoding":
		return encodingFuzz()
	default:
		return boundaryFuzz(original)
	}
}

// boundaryFuzz tests edge cases for the field's apparent type.
func boundaryFuzz(original string) string {
	// Detect numeric
	if _, err := strconv.ParseFloat(original, 64); err == nil {
		candidates := []string{
			"0", "-1", "-999999", "999999999", "2147483647", "-2147483648",
			"0.0", "99999.99", "-0.001", "NaN", "Inf", "-Inf",
			"1e308", "1e-308", "9" + strings.Repeat("9", 50),
		}
		return candidates[rand.Intn(len(candidates))] //nolint:gosec
	}
	// Detect date (8 or 14 digit numeric)
	if len(original) == 8 || len(original) == 14 {
		allDigits := true
		for _, c := range original {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			candidates := []string{
				"00000000", "99991231", "19000101", "29991231",
				"00000000000000", "99991231235959",
				"20240229", // valid leap day
				"20230229", // invalid leap day
			}
			return candidates[rand.Intn(len(candidates))] //nolint:gosec
		}
	}
	// String boundary
	candidates := []string{
		"",
		" ",
		strings.Repeat("A", 1),
		strings.Repeat("A", 255),
		strings.Repeat("A", 1024),
		strings.Repeat("A", 65535),
		"\x00",
		"\xFF",
		"null",
		"NULL",
		"undefined",
	}
	return candidates[rand.Intn(len(candidates))] //nolint:gosec
}

// injectionFuzz tests SQL, shell, script, and HL7 delimiter injection.
func injectionFuzz() string {
	payloads := []string{
		// SQL
		"' OR '1'='1",
		"'; DROP TABLE PATIENTS; --",
		"' UNION SELECT username,password FROM users--",
		"1; EXEC xp_cmdshell('whoami')--",
		"\" OR \"\"=\"",
		// Shell
		"$(whoami)",
		"`id`",
		"| cat /etc/passwd",
		"; ping -c 1 127.0.0.1",
		// XSS
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"javascript:alert(1)",
		// LDAP
		"*)(uid=*))(|(uid=*",
		// HL7 delimiter injection
		"TEST\rMSH|^~\\&|EVIL|FAC",
		"TEST\rRXE|1|MORPHINE|99999|MG",
		"TEST|INJECT^COMPONENT",
		// Path traversal
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\cmd.exe",
		// Null / control chars
		"\x00\x01\x02\x03",
		"\r\n\r\n",
	}
	return payloads[rand.Intn(len(payloads))] //nolint:gosec
}

// formatFuzz tests format string and special character handling.
func formatFuzz(original string) string {
	payloads := []string{
		"%s%s%s%s%s%s%s%s%s%s",
		"%d%d%d%d%d",
		"%x%x%x%x%x",
		"%-100s",
		"%n%n%n%n",
		"{{7*7}}",         // template injection
		"${7*7}",          // EL injection
		"#{7*7}",          // SpEL injection
		"\u0000",          // unicode null
		"\uFFFD",          // unicode replacement char
		"\u202E" + original, // right-to-left override
		strings.Repeat("%", 100),
		"\\x41\\x41\\x41",
		"AAAA" + strings.Repeat("\x41", 500), // buffer overflow pattern
	}
	return payloads[rand.Intn(len(payloads))] //nolint:gosec
}

// randomFuzz mutates the original value randomly.
func randomFuzz(original string) string {
	if len(original) == 0 {
		return randomString(rand.Intn(50) + 1) //nolint:gosec
	}
	runes := []rune(original)
	// Pick a random mutation strategy
	switch rand.Intn(5) { //nolint:gosec
	case 0: // bit flip at random position
		pos := rand.Intn(len(runes)) //nolint:gosec
		runes[pos] = rune(rand.Intn(128)) //nolint:gosec
		return string(runes)
	case 1: // duplicate
		return original + original
	case 2: // truncate
		if len(runes) > 1 {
			return string(runes[:rand.Intn(len(runes))]) //nolint:gosec
		}
		return ""
	case 3: // replace with random of same length
		return randomString(len(original))
	default: // append random suffix
		return original + randomString(rand.Intn(20)+1) //nolint:gosec
	}
}

// overflowFuzz generates very large values to probe buffer handling.
func overflowFuzz(original string) string {
	sizes := []int{256, 512, 1024, 4096, 16384, 65535, 131072}
	size := sizes[rand.Intn(len(sizes))] //nolint:gosec
	chars := []string{"A", "1", "\x00", "%", "'", "<"}
	char := chars[rand.Intn(len(chars))] //nolint:gosec
	return strings.Repeat(char, size)
}

// encodingFuzz tests unusual character encodings and escape sequences.
func encodingFuzz() string {
	payloads := []string{
		"\\E\\|\\E\\",          // HL7 escape: field separator
		"\\E\\^\\E\\",          // HL7 escape: component separator
		"\\E\\~\\E\\",          // HL7 escape: repetition separator
		"\\E\\&\\E\\",          // HL7 escape: subcomponent separator
		"\\H\\bold\\N\\",       // HL7 highlight escape
		"\\Zxxx\\",             // HL7 custom escape
		"\xef\xbf\xbd",        // UTF-8 replacement char
		"\xe2\x80\x8b",        // zero-width space
		string([]byte{0xC0, 0x80}), // overlong UTF-8
		"&#x3C;script&#x3E;",  // HTML entity XSS
		"%3Cscript%3E",        // URL encoded XSS
		"%00",                 // URL encoded null
		"\\u0000",             // JSON unicode null
	}
	return payloads[rand.Intn(len(payloads))] //nolint:gosec
}

// ─────────────────────────────────────────────────────────────────────────────
// Anomaly detection
// ─────────────────────────────────────────────────────────────────────────────

func detectFuzzAnomaly(response, ackCode, fuzzedVal string, dur time.Duration, start time.Time) string {
	var anomalies []string

	// Unexpected acceptance of clearly invalid data
	if ackCode == "AA" {
		if isObviouslyMalicious(fuzzedVal) {
			anomalies = append(anomalies, "⚠ AA on injection payload")
		}
	}

	// Error text leaks internal info
	if ackCode == "AE" || ackCode == "AR" {
		leaks := []string{"Exception", "StackTrace", "ORA-", "SQLSTATE", "C:\\", "/var/", "password=", "at System.", "at org."}
		upper := strings.ToUpper(response)
		for _, leak := range leaks {
			if strings.Contains(upper, strings.ToUpper(leak)) {
				anomalies = append(anomalies, "⚠ ERROR LEAKS: "+leak)
				break
			}
		}
	}

	// Fuzz value reflected in response
	if len(fuzzedVal) > 3 && strings.Contains(response, fuzzedVal) {
		anomalies = append(anomalies, "⚠ REFLECTED in response")
	}

	// Very slow response — possible DoS/hang
	if dur > 10*time.Second {
		anomalies = append(anomalies, fmt.Sprintf("⚠ SLOW %.1fs", dur.Seconds()))
	}

	// Empty response
	if len(strings.TrimSpace(response)) == 0 {
		anomalies = append(anomalies, "⚠ EMPTY response")
	}

	if len(anomalies) > 0 {
		return strings.Join(anomalies, " | ")
	}
	return ""
}

func isObviouslyMalicious(val string) bool {
	indicators := []string{
		"DROP TABLE", "UNION SELECT", "xp_cmdshell",
		"<script>", "$(", "`id`", "/etc/passwd",
		"\rMSH", "\rRXE",
	}
	upper := strings.ToUpper(val)
	for _, ind := range indicators {
		if strings.Contains(upper, strings.ToUpper(ind)) {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func mutateField(msg string, segIdx, fieldIdx int, newValue string) string {
	segs := splitSegments(msg)
	if segIdx >= len(segs) {
		return msg
	}
	fields := strings.Split(segs[segIdx], "|")
	for len(fields) <= fieldIdx {
		fields = append(fields, "")
	}
	fields[fieldIdx] = newValue
	segs[segIdx] = strings.Join(fields, "|")
	return strings.Join(segs, "\r")
}

func resolveStrategies(requested []string) []string {
	all := []string{"boundary", "injection", "format", "random", "overflow", "encoding"}
	for _, s := range requested {
		if strings.EqualFold(s, "all") {
			return all
		}
	}
	if len(requested) == 0 {
		return all
	}
	return requested
}

func randomString(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))] //nolint:gosec
	}
	return string(b)
}

// tagMSHIdentity overwrites MSH-3 and MSH-4 in a raw HL7 message
// so the receiver can distinguish tool messages from real device messages.
// Only clinical data (OBX values etc.) is left untouched.
//
// Safety guards:
//   - Skips MSH segments that have no field separator (deliberately malformed)
//   - Skips if the fuzz target was MSH field 3 or 4 (would corrupt the test)
//   - Requires at least 5 pipe-delimited fields to be a valid MSH
//   - Never modifies the encoding characters (MSH-1/MSH-2)
func tagMSHIdentity(msg, sendingApp, sendingFacility string) string {
	segs := splitSegments(msg)
	for i, seg := range segs {
		if !strings.HasPrefix(seg, "MSH") {
			continue
		}

		// Guard 1: must contain at least one field separator to be a valid MSH.
		// "MSHinvalid no field separators at all" has none — skip it entirely.
		if !strings.Contains(seg, "|") {
			break
		}

		fields := strings.Split(seg, "|")

		// Guard 2: must have at least 5 fields (MSH|FS|ENC|SendApp|SendFac|...)
		// to be structurally valid enough to tag safely.
		if len(fields) < 5 {
			break
		}

		// Guard 3: MSH-1 must be exactly one character (the field separator byte).
		// If it is longer, MSH is malformed — do not touch it.
		if len(fields[1]) != 1 {
			break
		}

		// Guard 4: MSH-2 must be exactly 4 characters (encoding chars ^~\&).
		// If not, this is a deliberately broken MSH — leave it alone.
		if len(fields[2]) != 4 {
			break
		}

		for len(fields) < 7 {
			fields = append(fields, "")
		}
		if sendingApp != "" {
			fields[3] = sendingApp
		}
		if sendingFacility != "" {
			fields[4] = sendingFacility
		}
		segs[i] = strings.Join(fields, "|")
		break // only tag the first MSH
	}
	return strings.Join(segs, "\r")
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

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\x00", "\\0")
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

// printSummary shows a summary of interesting findings after fuzzing.
func (fs *FuzzSession) printSummary() {
	fmt.Println()
	fmt.Println("  " + strings.Repeat("═", 70))
	fmt.Println("  FUZZ SESSION SUMMARY")
	fmt.Println("  " + strings.Repeat("─", 70))

	total := len(fs.results)
	var accepted, rejected, errors, anomalies int
	for _, r := range fs.results {
		switch r.ACKCode {
		case "AA":
			accepted++
		case "AE", "AR":
			rejected++
		default:
			if r.Error != "" {
				errors++
			}
		}
		if r.Anomaly != "" {
			anomalies++
		}
	}

	fmt.Printf("  Total sent : %d\n", total)
	fmt.Printf("  Accepted   : %d (AA)\n", accepted)
	fmt.Printf("  Rejected   : %d (AE/AR)\n", rejected)
	fmt.Printf("  Errors     : %d\n", errors)
	fmt.Printf("  Anomalies  : %d\n", anomalies)

	if anomalies > 0 {
		fmt.Println()
		fmt.Println("  ⚠  ANOMALOUS RESULTS (review these):")
		fmt.Println("  " + strings.Repeat("─", 70))
		for _, r := range fs.results {
			if r.Anomaly != "" {
				fmt.Printf("  [%04d] %s field %d  orig=%-15s  fuzz=%-20s\n",
					r.Iteration, r.SegID, r.FieldIndex,
					truncate(r.OrigValue, 15), truncate(r.FuzzedValue, 20))
				fmt.Printf("         Strategy=%-10s  ACK=%-4s  %s\n",
					r.Strategy, r.ACKCode, r.Anomaly)
			}
		}
	}
	fmt.Println("  " + strings.Repeat("═", 70))
}

// saveCSV writes all results to a CSV file for further analysis.
func (fs *FuzzSession) saveCSV() {
	f, err := os.Create(fs.cfg.OutputFile)
	if err != nil {
		fmt.Printf("  Could not write CSV: %v\n", err)
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	fmt.Fprintln(w, "Iteration,MessageID,Segment,Field,Strategy,OrigValue,FuzzedValue,ACKCode,DurationMs,Anomaly,Error")
	for _, r := range fs.results {
		fmt.Fprintf(w, "%d,%s,%s,%d,%s,%s,%s,%s,%d,%s,%s\n",
			r.Iteration,
			r.MessageID,
			r.SegID,
			r.FieldIndex,
			r.Strategy,
			csvEscape(r.OrigValue),
			csvEscape(r.FuzzedValue),
			r.ACKCode,
			r.Duration.Milliseconds(),
			csvEscape(r.Anomaly),
			csvEscape(r.Error),
		)
	}
	_ = w.Flush()
	fmt.Printf("  Results saved to: %s\n", fs.cfg.OutputFile)
}

func csvEscape(s string) string {
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\x00", "\\0")
	if strings.ContainsAny(s, ",\"") {
		s = "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}
