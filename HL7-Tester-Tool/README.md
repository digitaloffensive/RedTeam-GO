# HL7 Security Tester

A Go-based bidirectional HL7 v2.x security assessment tool for testing HIPAA compliance
and PHI protection in HL7 receivers. Includes a built-in message editor, auto-sanitizer,
fuzzer, ACK probe, and support for loading real captured messages from live systems.

---

## What It Tests

### Standard Tests

| Category | Tests |
|---|---|
| **Eavesdropping** | Plaintext connection rejection, PHI echoed in ACK responses |
| **TLS Quality** | TLS 1.0/1.1 rejected, TLS 1.2/1.3 accepted, cipher suite inspection |
| **Certificates** | Expiry, hostname match, key usage |
| **Replay Attacks** | Duplicate message ID detection, stale timestamp (48h) detection |
| **Denial of Service** | Connection flood / rate limiting, oversized message, slow client, malformed input (7 variants) |
| **PHI Exposure** | PHI fields echoed in ACK and NACK responses |

### Advanced Tests

| Category | Tests |
|---|---|
| **Segment Injection** | Embedded `\r` injection of fake RXE/DG1/MSH/Z-segments (Black Hat 2018 / ERNW 2020) |
| **Field Tampering** | Impossible clinical values — lethal doses, extreme lab results, allergy erasure |
| **Injection Attacks** | SQL, shell command, XSS, LDAP injection via PID/OBX/NTE fields |
| **Sender Spoofing** | Messages claiming to be HIS, LIS, PHARMACY, ADMIN, ROOT |
| **Patient Enumeration** | QRY^A19 unauthenticated access, differential ACK oracle attacks |
| **Error Leakage** | Stack traces, DB connection strings, file paths in NACK error text |
| **Audit Trail** | Response timing analysis, burst acceptance rate |
| **NACK PHI Leakage** | Canary patient identifiers echoed in rejection responses |

---

## Installation

Requires **Go 1.21+**.

```bash
git clone <repo>
cd hl7-security-tester
make build
./build/hl7-security-tester --help
```

Cross-compile for all platforms:
```bash
make build-all
```

Outputs:
```
build/hl7-security-tester-linux-amd64
build/hl7-security-tester-darwin-amd64
build/hl7-security-tester-darwin-arm64
build/hl7-security-tester-windows.exe
```

Cross-compile for Windows from Mac manually:
```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
go build -trimpath -ldflags="-s -w" -o hl7-security-tester.exe ./cmd/...
```

---

## Quick Start

```bash
# Step 1 — probe first to confirm receiver accepts messages
./hl7-security-tester -host 10.0.0.5 -port 2575 -tls-auto -probe

# Step 2 — run all security tests
./hl7-security-tester -host 10.0.0.5 -port 2575 -tls-auto -file testdata/sample_messages.hl7

# Step 3 — JSON report for audit trail
./hl7-security-tester -host 10.0.0.5 -port 2575 -tls-auto \
  -file testdata/sample_messages.hl7 -output json -out-file report.json
```

---

## All Flags

### BASIC

| Flag | Default | Description |
|---|---|---|
| `-host` | `localhost` | Target HL7 receiver hostname or IP |
| `-port` | `2575` | Target port |
| `-file` | | HL7 message file to send |
| `-tests` | `all` | Comma-separated tests to run (see full list below) |
| `-debug` | `false` | Verbose debug logging |

### TLS

| Flag | Description |
|---|---|
| `-tls-auto` | **Zero-config TLS.** No certificates required. Connects and encrypts automatically, accepting any server certificate. Ideal for assessment when CA file is not available. Combine with `-cert`/`-key` only if the server requires mutual TLS. |
| `-tls` | Full TLS with certificate verification. Uses system roots unless `-ca` is provided. |
| `-ca` | CA certificate (PEM) for server verification. When used with `-tls-auto`, enables full chain validation instead of accept-any-cert. |
| `-cert` | Client certificate (PEM). Only needed when the **server** requires mutual TLS (mTLS). |
| `-key` | Client private key (PEM). Required only alongside `-cert`. |
| `-skip-verify` | Disable certificate verification entirely. INSECURE — used internally by TLS downgrade tests. |

**TLS mode quick reference:**

| Scenario | Flags |
|---|---|
| No TLS (plaintext) | *(no TLS flags)* |
| TLS, no certs needed | `-tls-auto` |
| TLS + verify server cert | `-tls -ca ca.pem` |
| TLS + server requires client cert | `-tls-auto -cert client.pem -key client.key` |

> Note: `-tls` and `-tls-auto` are mutually exclusive. Providing `-cert`/`-key` with `-tls-auto` triggers a warning since client certs are only needed when the server explicitly requires mTLS.

### TIMEOUTS

| Flag | Default | Description |
|---|---|---|
| `-timeout` | `10s` | TCP connection timeout |
| `-ack-timeout` | `60s` | How long to wait for an ACK. Accepts Go durations: `30s`, `2m`, `120s`. |
| `-read-timeout` | | Alias for `-ack-timeout` — both work identically |
| `-no-response` | `false` | Do not wait for an ACK at all. Use when the receiver never ACKs (e.g. medical devices that broadcast-only). |

### AUTHENTICATION

| Flag | Description |
|---|---|
| `-msh-sending-app` | MSH-3: your sending application name. Overrides value in message file. |
| `-msh-sending-facility` | MSH-4: your sending facility name. |
| `-msh-receiving-app` | MSH-5: target application name. |
| `-msh-receiving-facility` | MSH-6: target facility name. |
| `-pre-auth` | Raw string to send immediately after TCP/TLS connect, before any MLLP. Use when the server issues a login challenge on connect. |

> If you get "Authentication failed" errors, the receiver is rejecting MSH-3/4/5/6. Ask the system admin for the exact expected values and pass them with these flags — they overwrite whatever is in your message file.

### SANITIZE

Automatically fixes common ACK-blocking issues before sending captured messages.

| Flag | Default | Description |
|---|---|---|
| `-sanitize` | `false` | Auto-fix issues: fills missing MSH-7/10/12, removes SFT/UAC, removes empty FT1, fills missing PID-3/PID-5, ensures OBX-11 present. Prints a fix report before sending. |
| `-sanitize-mrn` | `TEST001` | Default MRN when PID-3 is empty |
| `-sanitize-name` | `TESTPATIENT^TEST` | Default patient name when PID-5 is empty |
| `-sanitize-version` | | HL7 version for empty MSH-12 (e.g. `2.5` or `2.6`) |

### DOS TUNING

| Flag | Default | Description |
|---|---|---|
| `-flood-conns` | `50` | Connections for flood test |
| `-flood-concurrency` | `10` | Concurrent connections during flood test |
| `-slow-hold` | `10s` | Idle hold duration for slow-client test |
| `-oversize-mb` | `10` | Size in MB for the oversized message test. Increase to stress-test buffer limits: `-oversize-mb 50` |

### OUTPUT

| Flag | Default | Description |
|---|---|---|
| `-output` | `text` | Output format: `text` or `json` |
| `-out-file` | stdout | Write report to this file |

### MODES

| Flag | Description |
|---|---|
| `-probe` | Send a minimal ADT^A01 probe and verify ACK AA before any other tests. Diagnoses connection failures, MLLP issues, ACK codes, and MSH identity problems with specific fix suggestions. **Run this first.** |
| `-skip-probe` | Skip the automatic ACK probe that runs before security tests. |
| `-interactive` | Launch interactive shell for manual testing |
| `-edit` | Launch the message editor |
| `-fuzz <file>` | Load a captured HL7 file and fuzz its fields while sending live |
| `-pcap <file>` | Extract HL7 messages from a `.pcap` or `.pcapng` network capture file. No connection to the receiver needed — reads HL7 directly from captured traffic. |
| `-pcap-out <file>` | Save messages extracted by `-pcap` to a `.hl7` file for immediate use with `-file` |
| `-scan <target>` | Scan a host or CIDR range for open HL7 MLLP listeners. Examples: `-scan 10.0.0.1` or `-scan 10.0.0.0/24` |
| `-scan-ports <ports>` | Comma-separated ports to probe during `-scan` (default: `2575,2576,6661,6662,8080,8443,8888,9090`) |

### FUZZER FLAGS

| Flag | Default | Description |
|---|---|---|
| `-fuzz` | | Path to captured HL7 file to fuzz |
| `-fuzz-iter` | `100` | Number of fuzz iterations |
| `-fuzz-delay` | `100` | Milliseconds between sends. `0` = no delay (maximum speed) |
| `-fuzz-strategy` | `all` | Strategies: `boundary`, `injection`, `format`, `random`, `overflow`, `encoding`, `all` |
| `-fuzz-seg` | | Only fuzz this segment type (e.g. `OBX`, `PID`). Empty = all segments. |
| `-fuzz-field` | `0` | Only fuzz this field number. `0` = all fields. |
| `-fuzz-out` | | Save results to this CSV file |
| `-fuzz-stop-on-crash` | `false` | Stop if server stops responding (3 consecutive connection failures) |
| `-fuzz-tag` | `SECTEST` | Prefix embedded in every fuzz message ID (MSH-10) for log identification |
| `-fuzz-sending-app` | | Override MSH-3 on all fuzz messages to tag them in receiver logs |
| `-fuzz-sending-facility` | | Override MSH-4 on all fuzz messages |

---

## Available Tests

Pass a comma-separated list to `-tests`, or use `all` (default).

### Standard Tests

| Name | What it checks | Severity |
|---|---|---|
| `encryption` | Plaintext connection rejection, PHI echoed in ACK | CRITICAL |
| `tls` | TLS 1.0/1.1 rejected, TLS 1.2/1.3 accepted | HIGH |
| `cert` | Certificate expiry, hostname match, key usage | HIGH |
| `replay` | Duplicate message ID detection | HIGH |
| `timestamp` | Stale 48-hour-old timestamp accepted | HIGH |
| `flood` | Connection rate limiting | HIGH |
| `oversize` | Message size limit enforcement | HIGH |
| `malformed` | 7 variants of structurally invalid input | MEDIUM |
| `slow` | Idle connection timeout enforcement | MEDIUM |
| `phi` | PHI fields echoed in ACK responses | HIGH |

### Advanced Tests

| Name | What it checks | Severity |
|---|---|---|
| `seginject` | Segment injection via embedded `\r` (Black Hat 2018/ERNW 2020) — fake RXE, DG1, second MSH, Z-segment privilege escalation | CRITICAL |
| `tampering` | Impossible clinical values: 99999mg medication dose, WBC 999999, future DOB year 2999, allergy erasure | CRITICAL |
| `injection` | SQL DROP TABLE, UNION SELECT, xp_cmdshell, shell substitution, XSS, LDAP injection in PID/OBX/NTE/MSH fields | HIGH |
| `spoof` | Unauthorized sender — messages from HIS, LIS, PHARMACY, ADMIN, SUPERUSER, ROOT | CRITICAL |
| `enum` | Patient record enumeration via QRY^A19, differential ACK response analysis | CRITICAL |
| `errleakage` | Stack traces, DB connection strings, file paths, passwords in NACK error text | HIGH |
| `audit` | Audit trail weakness via response timing analysis and burst acceptance | MEDIUM |
| `nackleak` | PHI (MRN, name, SSN) echoed in NACK/rejection responses | HIGH |

**Examples:**
```bash
-tests all
-tests replay,timestamp
-tests seginject,tampering,injection,spoof
-tests encryption,tls,cert
-tests flood,oversize,malformed,slow
-tests errleakage,nackleak,enum,audit
```

---

## ACK Probe

The probe runs automatically before every test run. It sends the simplest
possible valid HL7 ADT^A01 and verifies the receiver returns ACK AA.

```bash
# Run probe standalone
./hl7-security-tester -host 10.0.0.5 -port 2575 -tls-auto -probe

# Skip the auto-probe before tests
./hl7-security-tester -host 10.0.0.5 -port 2575 -tls-auto \
  -file messages.hl7 -skip-probe
```

**What it diagnoses:**

| Symptom | Diagnosis provided |
|---|---|
| Cannot connect | Hostname/port/firewall/TLS version suggestions |
| Connection dropped | MSH identity mismatch, pre-auth requirement |
| ACK=AR | Sender authentication rejection with exact fix instructions |
| ACK=AE | Application-level error with error text from receiver |
| No response | Suggests `-ack-timeout` increase or `-no-response` |
| Empty response | Pre-auth challenge detection, non-standard ACK format |

If the probe fails before security tests, the user is shown the full diagnosis
and asked whether to continue. Use `-skip-probe` to bypass.

---

## Sanitizer

Fixes common ACK-blocking issues in captured messages before sending.
Prints a full fix report so you can see exactly what changed.

```bash
./hl7-security-tester -host 10.0.0.5 -port 2575 -tls-auto \
  -file captured_vitals.hl7 \
  -sanitize \
  -sanitize-version 2.6 \
  -msh-sending-app "Sending application"
```

**Fixes applied automatically:**
- Fills missing MSH-7 (timestamp), MSH-10 (unique message ID), MSH-12 (version)
- Removes SFT and UAC segments (not universally supported)
- Removes completely empty FT1 segments
- Fills missing PID-3 (MRN) with `-sanitize-mrn` value
- Fills missing/blank PID-5 (patient name) with `-sanitize-name` value
- Ensures OBX-11 result status is present on every OBX segment
- Regenerates MSH-10 to guarantee uniqueness per send

**From the editor shell:**
```
editor> sanitize          # fix all messages
editor> sanitize 1        # fix only message 1
editor> sanitize -mrn MRN001 -version 2.6
```

---

## Message Editor

Interactive editor for building, modifying, and pasting HL7 messages.

```bash
# Standalone editor mode
./hl7-security-tester -file messages.hl7 -edit

# From inside the interactive shell
hl7sec> edit
```

### Commands

```
VIEWING
  list              List all messages with summary
  show [n]          Show all segments of message n (default: 1)
  validate [n]      Check HL7 structural validity

CREATING / PASTING
  new               Create a blank ADT^A01 template
  paste [n]         Paste real HL7 from your system (replaces message n if given)
  dup <n>           Duplicate message n with new ID and timestamp
  import <file>     Append all messages from another .hl7 file

EDITING
  add-seg <n> <SEG>              Append segment to message n
  add-seg <n> after <s> <SEG>   Insert after segment number s
  del-seg <n> <s>               Delete segment s from message n
  edit <n> <s>                  Interactively edit fields of segment s
  set <n> <s> <f> <value>       Set field f of segment s directly

SANITIZE
  sanitize [n]      Fix ACK-blocking issues in all messages or just message n

MANAGING
  del-msg <n>       Delete entire message n
  save [path]       Save all messages (default: original file)
  export <n> <path> Export single message to its own file

FUZZER (from editor)
  fuzz <file> [options]   Fuzz a captured file — see options below

NAVIGATION
  done              Return to main shell
```

### Paste Example

```
editor> paste
  > MSH|^~\&|REALAPP|REALFAC|RECV|RECV|20240315150000||ORU^R01|MSG999|P|2.5
  > PID|1||MRN99999^^^HOSP||SMITH^JANE||19751220|F
  > OBX|1|NM|WBC^WHITE BLOOD COUNT||5.8|10*3/uL|4.5-11.0|N|||F
  > END
```

Type `END` or leave a blank line to finish. The tool validates and shows a summary.

### Adding OBX Segments

```
editor> add-seg 1 OBX|1|NM|WBC^WHITE BLOOD COUNT||7.2|10*3/uL|4.5-11.0|N|||F
editor> add-seg 1 OBX|2|NM|RBC^RED BLOOD CELLS||4.5|M/uL|4.2-5.4|N|||F
editor> add-seg 1 NTE|1|L|Patient fasting 8 hours prior to draw
editor> save
```

### Insert at Specific Position

```
editor> show 1                               # note segment numbers
editor> add-seg 1 after 3 DG1|1||I10^HYPERTENSION^ICD10
```

---

## PCAP Analyser

Extracts HL7 messages directly from a Wireshark or tcpdump network capture file.
No connection to the receiver is needed — reads raw TCP streams from the capture,
reassembles them, strips MLLP framing, and pulls out every HL7 message found.

Supports `.pcap` (legacy) and `.pcapng` (modern) formats. Pure Go — no libpcap,
no Wireshark installation, no Python required.

```bash
# Extract and display messages from a capture
./hl7-security-tester -pcap capture.pcap

# Extract and save to a file for immediate use in testing
./hl7-security-tester -pcap capture.pcap -pcap-out extracted.hl7

# Then test with the extracted real messages
./hl7-security-tester -host 10.0.0.5 -port 2575 -tls-auto -file extracted.hl7
```

**What the PCAP report shows:**
- Total packets and HL7 packets identified
- Communication flow map — source IP/port → destination IP/port, message count, message types
- All unique endpoints observed
- Per-message detail: timestamp, type, ID, sending app, PHI fields detected

**Typical workflow with a span port or TAP:**
1. Capture traffic on the clinical network with Wireshark or tcpdump
2. Save as `.pcap` or `.pcapng`
3. Run `-pcap capture.pcap -pcap-out real_messages.hl7`
4. Use `-file real_messages.hl7` to test with the exact messages the real devices send

---

## HL7 Port Scanner

Scans a host or network range to discover HL7 MLLP listeners. For each open port
it runs an MLLP probe to confirm it is actually an HL7 receiver — not just an open
TCP port.

```bash
# Scan a single host on all default HL7 ports
./hl7-security-tester -scan 10.0.0.5

# Scan a subnet (supports /24 and smaller CIDR ranges)
./hl7-security-tester -scan 10.0.0.0/24

# Scan custom ports
./hl7-security-tester -scan 10.0.0.0/24 -scan-ports 2575,2576,6661,9090

# Scan with TLS probe (tries TLS if plaintext gets no HL7 response)
./hl7-security-tester -scan 10.0.0.5 -tls-auto
```

Default ports probed: `2575`, `2576`, `6661`, `6662`, `8080`, `8443`, `8888`, `9090`

---

## Fuzzer

Loads real captured HL7 from a file and automatically mutates field values
while sending live to the target. Identifies how the receiver handles
malformed, boundary, and malicious input.

```bash
./hl7-security-tester -fuzz captured_vitals.hl7 \
  -host 10.0.0.5 -port 2575 -tls-auto \
  -fuzz-sending-app HL7SECTEST \
  -fuzz-sending-facility PENTEST \
  -fuzz-tag SECTEST \
  -fuzz-delay 0 \
  -fuzz-iter 500 \
  -fuzz-out results.csv
```

### Fuzz Strategies

| Strategy | Payloads |
|---|---|
| `boundary` | Empty, 65535-char strings, impossible dates, max integers, `NaN`, `Inf`, null bytes |
| `injection` | SQL `DROP TABLE`/`UNION SELECT`/`xp_cmdshell`, shell `$(whoami)`, XSS, LDAP, `\r` segment injection |
| `format` | `%s%s%s`, `%n`, `{{7*7}}`, `${7*7}`, Unicode null, right-to-left override |
| `random` | Bit flips, duplication, truncation, random same-length values |
| `overflow` | 256 / 512 / 1024 / 4096 / 65535 / 131072 byte payloads |
| `encoding` | HL7 escape sequences, overlong UTF-8, URL encoding, HTML entities, zero-width spaces |

### Anomaly Flags in Output

| Flag | Meaning |
|---|---|
| `⚠ AA on injection payload` | Server accepted a clearly malicious value |
| `⚠ ERROR LEAKS: Exception` | Error response reveals internal stack trace |
| `⚠ REFLECTED in response` | Payload echoed back — possible injection vector |
| `⚠ SLOW 12.3s` | Server hung processing the payload |
| `⚠ EMPTY response` | Server sent nothing back |

### Tagging Fuzz Messages

`-fuzz-sending-app`, `-fuzz-sending-facility`, and `-fuzz-tag` mark every tool
message in receiver logs so they are instantly distinguishable from real device
messages without touching any clinical data.

| Field | Real Device | Fuzzer |
|---|---|---|
| MSH-3 | `Sending application` | `HL7SECTEST` |
| MSH-4 | `Sending facility` | `PENTEST` |
| MSH-10 | `5074946058641026799` | `SECTEST000042` |

**Safety:** The tagging logic validates MSH structure before writing. Deliberately
malformed test payloads (no field separators, wrong encoding chars) are never
modified. When the fuzz target is MSH field 3 or 4, tagging is skipped for that
iteration to preserve the test payload.

### From the Editor Shell

```
editor> fuzz captured.hl7 -host 10.0.0.5 -port 2575 -tls-auto -iter 200
editor> fuzz captured.hl7 -host 10.0.0.5 -port 2575 -seg PID -strategy injection
editor> fuzz captured.hl7 -host 10.0.0.5 -port 2575 -iter 500 -out results.csv
```

---

## Interactive Shell

```bash
./hl7-security-tester -host 10.0.0.5 -port 2575 -file messages.hl7 -interactive
```

| Command | Description |
|---|---|
| `list` | List loaded messages |
| `parse <n>` | Show parsed fields of message n |
| `connect` | Open a persistent connection |
| `disconnect` | Close the connection |
| `send <n>` | Send message n and display response |
| `send-raw <file>` | Send raw file contents as HL7 |
| `replay` | Replay attack test |
| `timestamp` | Timestamp replay test |
| `flood <n>` | Connection flood with n connections |
| `oversize` | Send oversized message |
| `slow <secs>` | Slow client idle test |
| `malformed` | All malformed message variants |
| `tls` | TLS version tests |
| `cert` | Certificate validity tests |
| `phi` | Scan messages for PHI fields |
| `edit` | Open message editor |
| `quit` | Exit |

---

## Understanding Results

| Severity | Meaning |
|---|---|
| `CRITICAL` | Immediate risk — plaintext PHI, no auth, replays accepted, patient data exposed |
| `HIGH` | Significant risk — deprecated TLS, no rate limiting, stale timestamps, PHI in errors |
| `MEDIUM` | Moderate risk — weak input validation, missing size limits, audit weakness |
| `LOW` | Minor issues |
| `INFO` | Informational — no action required |
| `PASS` | Test passed |

---

## HL7 Version Detection

The version is always **MSH-12** — the 12th pipe-delimited field:

```
MSH|^~\&|APP|FAC|RECV|FAC|20240315||ORU^R01|MSG001|P|2.6
  1   2    3    4    5    6    7      8    9      10   11 12
```

Field 12 = `2.6`. Common versions: `2.3`, `2.4`, `2.5`, `2.5.1`, `2.6`.

---

## Troubleshooting

**"Authentication failed" on connect**
```bash
-msh-sending-app "ExactName" -msh-receiving-app "ExactName"
```

**"i/o timeout" / no ACK**
```bash
-ack-timeout 120s    # increase wait
-no-response         # skip waiting (for broadcast-only devices)
```

**"EOF" / connection dropped immediately**
1. Wrong MSH identity → use `-msh-sending-app`
2. Structural message issues → use `-sanitize`
3. Pre-auth challenge → use `-pre-auth`

**"0 bytes from transport stream" on receiver**
MLLP framing issue. Use `-sanitize` to normalize line endings.

**PHI echoed in disconnect message**
The receiver is parsing the message before dropping it — transport is working.
The disconnect is application-level (MSH identity). Fix with `-msh-sending-app`.

---

## Architecture

```
cmd/main.go                     CLI, flag parsing, all mode entry points
pkg/hl7/message.go              HL7 v2.x parser, MLLP framing, PHI scanner
pkg/transport/client.go         TCP/TLS connection, bidirectional send/receive,
                                MSH identity rewriting, pre-auth handshake
pkg/transport/probe.go          ACK probe with full diagnostic reporting
pkg/security/tests.go           Standard security tests (encryption, TLS, replay, DoS, PHI)
pkg/security/advanced_tests.go  Advanced tests (injection, tampering, spoof, enum,
                                error leakage, audit trail, NACK PHI)
pkg/editor/editor.go            Interactive message editor shell
pkg/editor/fuzzer.go            Field fuzzer with 6 strategies and anomaly detection
pkg/editor/sanitizer.go         Auto-sanitizer for captured messages
pkg/reporter/report.go          Text and JSON report generation
pkg/pcap/pcap.go                Pure-Go PCAP/PCAPNG parser and HL7 stream extractor
testdata/sample_messages.hl7    Sample ADT, ORU, RDE messages
testdata/captured_vitals.hl7    Real captured ventilator/patient monitor message
```

---

## Common Workflows

**Discover unknown HL7 listeners on a network:**
```bash
./hl7-security-tester -scan 10.0.0.0/24
./hl7-security-tester -scan 172.31.0.0/24 -tls-auto
```

**Extract messages from a network capture then test with them:**
```bash
./hl7-security-tester -pcap hospital_traffic.pcap -pcap-out real_messages.hl7
./hl7-security-tester -host 10.0.0.5 -port 2575 -tls-auto -file real_messages.hl7 -sanitize
```

**First run against a new receiver:**
```bash
./hl7-security-tester -host 10.0.0.5 -port 2575 -tls-auto -probe
./hl7-security-tester -host 10.0.0.5 -port 2575 -tls-auto \
  -file testdata/sample_messages.hl7 -debug
```

**Captured message not getting ACK:**
```bash
./hl7-security-tester -host 10.0.0.5 -port 2575 -tls-auto \
  -file testdata/captured_vitals.hl7 \
  -sanitize -sanitize-version 2.6 \
  -msh-sending-app "Sending application" \
  -no-response
```

**Full assessment with JSON report:**
```bash
./hl7-security-tester -host 10.0.0.5 -port 2575 -tls-auto \
  -file testdata/sample_messages.hl7 \
  -tests all \
  -output json -out-file report.json
```

**Fuzz OBX value fields only (ventilator/patient monitor):**
```bash
./hl7-security-tester -fuzz testdata/captured_vitals.hl7 \
  -host 10.0.0.5 -port 2575 -tls-auto \
  -fuzz-seg OBX -fuzz-field 5 \
  -fuzz-strategy boundary,injection \
  -fuzz-sending-app HL7SECTEST -fuzz-tag FUZZ \
  -fuzz-delay 10 -fuzz-iter 300 -fuzz-out obx_results.csv
```

**Oversized message test beyond default 10 MB:**
```bash
./hl7-security-tester -host 10.0.0.5 -port 2575 -tls-auto \
  -file testdata/sample_messages.hl7 -tests oversize -oversize-mb 50
```

**Replay and DoS tests only:**
```bash
./hl7-security-tester -host 10.0.0.5 -port 2575 -tls-auto \
  -file testdata/sample_messages.hl7 \
  -tests replay,timestamp,flood,oversize,slow
```

**Advanced injection and spoofing tests:**
```bash
./hl7-security-tester -host 10.0.0.5 -port 2575 -tls-auto \
  -file testdata/sample_messages.hl7 \
  -tests seginject,tampering,injection,spoof,enum,errleakage,nackleak
```

**Test against the vulnerable listener (Linux):**
```bash
# Start vulnerable listener on test machine
./hl7-vulnerable-listener -port 2575

# Run all tests against it — all should FAIL (demonstrates detections)
./hl7-security-tester -host testmachine -port 2575 \
  -file testdata/sample_messages.hl7 -tests all -skip-probe

# Run against fixed mode — all should PASS (no false positives)
./hl7-vulnerable-listener -port 2576 -mode fixed &
./hl7-security-tester -host testmachine -port 2576 \
  -file testdata/sample_messages.hl7 -tests all -skip-probe
```

---

## Message File Format

Messages separated by blank lines (recommended):
```
MSH|^~\&|APP|FAC|RECV|FAC|20240315||ADT^A01|MSG001|P|2.5
PID|1||MRN001^^^HOSP||DOE^JOHN||19800515|M

MSH|^~\&|LAB|LAB_FAC|RECV|FAC|20240315||ORU^R01|MSG002|P|2.5
PID|1||MRN001^^^HOSP||DOE^JOHN
OBX|1|NM|WBC^WHITE BLOOD COUNT||7.2|10*3/uL|4.5-11.0|N|||F
```

- `\r`, `\r\n`, and `\n` segment separators all handled automatically
- Multiple messages in one file are split on `MSH` boundaries
- HTML entities in unit fields (e.g. `cmH<sub>2</sub>O`) are cleaned by the sanitizer

---

## Legal & Ethical Notice

This tool is for **authorized security assessments only**. Always obtain written
permission before testing systems that handle Protected Health Information (PHI).
Unauthorized testing of healthcare systems may violate HIPAA and computer fraud laws.
