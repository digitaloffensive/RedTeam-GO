# HL7 Security Tester

A bidirectional HL7 v2.x security assessment tool for testing HIPAA compliance
and PHI protection in HL7 receivers. Tests for eavesdropping, replay attacks,
denial of service, injection vulnerabilities, and PHI leakage. Includes a
built-in message editor, fuzzer, and auto-sanitizer for captured messages.

---

## Contents of This Package

```
hl7-security-tester.exe     Main tool — all features in one binary
sample_messages.hl7         Sample ADT, ORU, and RDE messages for testing
captured_vitals.hl7         Real captured ventilator/patient monitor message
RUN_ME.bat                  Quick-start examples
README.md                   This file
```

---

## System Requirements

- Windows 10 / Windows Server 2016 or later (64-bit)
- No installation required — standalone executable
- Network access to the HL7 receiver under test

---

## Quick Start

Open **Command Prompt** or **PowerShell** in this folder, then:

```cmd
REM Step 1 — probe the receiver first (confirms it is accepting messages)
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto -probe

REM Step 2 — run all security tests
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto -file sample_messages.hl7

REM Step 3 — save a JSON report for audit trail
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto -file sample_messages.hl7 ^
  -output json -out-file report.json
```

---

## All Flags

### BASIC

| Flag | Default | Description |
|---|---|---|
| `-host` | `localhost` | Target HL7 receiver hostname or IP |
| `-port` | `2575` | Target port |
| `-file` | | HL7 message file to send |
| `-tests` | `all` | Tests to run — see full list below |
| `-debug` | `false` | Verbose debug logging |

### TLS

| Flag | Description |
|---|---|
| `-tls-auto` | **Recommended.** Connect with TLS, no certificates needed. Accepts any server certificate automatically. Use this for most assessments. |
| `-tls` | Connect with TLS and full certificate verification. Requires `-ca` or system roots. |
| `-ca` | CA certificate file (PEM) to verify the server. When used with `-tls-auto` enables full chain validation. |
| `-cert` | Client certificate (PEM). Only needed when the **server** requires mutual TLS (mTLS) from clients. |
| `-key` | Client private key (PEM). Required only alongside `-cert`. |
| `-skip-verify` | Disable TLS certificate verification entirely. INSECURE — used internally by TLS downgrade tests. |

**TLS mode summary:**

| Scenario | Flags to use |
|---|---|
| No TLS (plaintext) | *(no TLS flags)* |
| TLS, no cert files | `-tls-auto` |
| TLS + verify server cert | `-tls -ca ca.pem` |
| TLS + server requires client cert | `-tls-auto -cert client.pem -key client.key` |

**Extracting a PFX certificate with PowerShell (no OpenSSL needed):**
```powershell
$pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
    "C:\path\to\cert.pfx", "YourPassword",
    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

$certB64 = [Convert]::ToBase64String($pfx.RawData, [Base64FormattingOptions]::InsertLineBreaks)
"-----BEGIN CERTIFICATE-----`n$certB64`n-----END CERTIFICATE-----" | Out-File client.pem -Encoding ASCII

$key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($pfx)
$keyB64 = [Convert]::ToBase64String(
    $key.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob),
    [Base64FormattingOptions]::InsertLineBreaks)
"-----BEGIN PRIVATE KEY-----`n$keyB64`n-----END PRIVATE KEY-----" | Out-File client.key -Encoding ASCII
```

### TIMEOUTS

| Flag | Default | Description |
|---|---|---|
| `-timeout` | `10s` | TCP connection timeout |
| `-ack-timeout` | `60s` | How long to wait for an ACK. Accepts Go durations: `30s`, `2m`, `120s`. |
| `-read-timeout` | | Alias for `-ack-timeout` |
| `-no-response` | `false` | Do not wait for an ACK at all. Use when the receiver never ACKs (e.g. medical devices that broadcast-only). |

### AUTHENTICATION

| Flag | Description |
|---|---|
| `-msh-sending-app` | MSH-3: your sending application name. Set to the exact value the receiver expects. |
| `-msh-sending-facility` | MSH-4: your sending facility name. |
| `-msh-receiving-app` | MSH-5: the target application name. |
| `-msh-receiving-facility` | MSH-6: the target facility name. |
| `-pre-auth` | Raw string to send immediately after connect, before MLLP. For servers that issue a login challenge on connect. |

**If you get "Authentication failed" errors**, the receiver is rejecting your MSH
identity. Ask the system administrator for the exact values they expect, then:
```cmd
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto ^
  -msh-sending-app "MySystem" ^
  -msh-sending-facility "MyHospital" ^
  -msh-receiving-app "Rhapsody" ^
  -msh-receiving-facility "DestHosp" ^
  -file sample_messages.hl7
```

### SANITIZE

Automatically fixes common issues in captured messages before sending.
Use this when loading real captured HL7 that is not getting an ACK.

| Flag | Default | Description |
|---|---|---|
| `-sanitize` | `false` | Auto-fix ACK-blocking issues: fills missing MSH fields, removes unsupported SFT/UAC segments, removes empty FT1 segments, fills missing PID-3/PID-5, ensures OBX-11 is present. |
| `-sanitize-mrn` | `TEST001` | Default MRN when PID-3 is empty |
| `-sanitize-name` | `TESTPATIENT^TEST` | Default patient name when PID-5 is empty |
| `-sanitize-version` | | HL7 version for empty MSH-12 (e.g. `2.5` or `2.6`) |

### DOS TUNING

| Flag | Default | Description |
|---|---|---|
| `-flood-conns` | `50` | Number of connections for flood test |
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
| `-probe` | Send a minimal ADT^A01 probe and verify ACK AA. **Run this first** before any other tests. Diagnoses connection, MLLP framing, ACK code, and MSH identity issues with specific fix suggestions. |
| `-skip-probe` | Skip the automatic probe that runs before security tests. |
| `-interactive` | Launch interactive shell for manual message sending and testing. |
| `-edit` | Launch the message editor to build, modify, or paste HL7 messages. |
| `-fuzz` | Load a captured HL7 file and fuzz its field values while sending live. See fuzzer section. |
| `-pcap <file>` | Extract HL7 messages from a `.pcap` or `.pcapng` network capture. No receiver connection needed. |
| `-pcap-out <file>` | Save messages extracted by `-pcap` to a `.hl7` file for use with `-file` |
| `-scan <target>` | Scan a host or CIDR for open HL7 MLLP listeners. Example: `-scan 172.31.0.0/24` |
| `-scan-ports <list>` | Ports to probe during `-scan` (default: `2575,2576,6661,6662,8080,8443,8888,9090`) |

---

## Security Tests

Pass a comma-separated list to `-tests`, or use `all` (default).

### Standard Tests

| Name | What it checks | Severity |
|---|---|---|
| `encryption` | Plaintext connection rejection, PHI echoed in ACK | CRITICAL |
| `tls` | TLS 1.0/1.1 rejected, TLS 1.2/1.3 accepted | HIGH |
| `cert` | Certificate expiry, hostname match, key usage | HIGH |
| `replay` | Duplicate message ID detection | HIGH |
| `timestamp` | Stale timestamp (48h old) accepted | HIGH |
| `flood` | Connection rate limiting | HIGH |
| `oversize` | Message size limit enforcement | HIGH |
| `malformed` | 7 variants of structurally invalid input | MEDIUM |
| `slow` | Idle connection timeout enforcement | MEDIUM |
| `phi` | PHI fields echoed in ACK responses | HIGH |

### Advanced Tests

| Name | What it checks | Severity |
|---|---|---|
| `seginject` | Segment injection via embedded `\r` in field values (Black Hat 2018 / ERNW 2020 attack vectors — fake RXE/DG1/MSH injection) | CRITICAL |
| `tampering` | Impossible clinical values: lethal medication dose, extreme lab results, future DOB, allergy erasure | CRITICAL |
| `injection` | SQL DROP TABLE, UNION SELECT, xp_cmdshell, shell substitution, XSS, LDAP injection in patient fields | HIGH |
| `spoof` | Unauthorized sender — messages claiming to be HIS, LIS, PHARMACY, ADMIN, ROOT | CRITICAL |
| `enum` | Patient record enumeration via QRY^A19 — unauthenticated access, differential ACK responses | CRITICAL |
| `errleakage` | Stack traces, DB connection strings, file paths in NACK error text | HIGH |
| `audit` | Audit trail weakness — response timing analysis, burst acceptance rate | MEDIUM |
| `nackleak` | PHI echoed in NACK responses (canary patient name/MRN/SSN) | HIGH |

**Example combinations:**
```cmd
-tests all
-tests replay,timestamp
-tests seginject,tampering,injection,spoof
-tests encryption,tls,cert
-tests flood,oversize,malformed,slow
```

---

## ACK Probe

**Always run the probe first before any other tests.** It sends the simplest
possible valid HL7 message and tells you exactly what is wrong if no ACK comes back.

```cmd
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto -probe
```

**What it diagnoses:**

- Cannot connect → checks hostname, port, firewall, TLS version
- Connection dropped → checks MSH identity, pre-auth requirements
- ACK=AR → identifies sender authentication as the likely cause with fix instructions
- ACK=AE → identifies application-level rejection with error text
- No response → suggests `-ack-timeout` increase or `-no-response`

The probe also runs automatically before security tests. If it fails you are
asked whether to continue. Use `-skip-probe` to bypass this.

---

## Sanitizer

When loading real captured HL7 messages that are not getting an ACK, use
`-sanitize` to automatically fix the most common issues:

```cmd
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto ^
  -file captured_vitals.hl7 ^
  -sanitize ^
  -sanitize-version 2.6 ^
  -msh-sending-app "Sending application"
```

**What it fixes automatically:**
- Fills missing MSH-7 (timestamp), MSH-10 (unique message ID), MSH-12 (version)
- Removes SFT and UAC segments (not supported by all receivers)
- Removes completely empty FT1 segments
- Fills missing PID-3 (MRN) with `-sanitize-mrn` value
- Fills missing/blank PID-5 (patient name) with `-sanitize-name` value
- Ensures OBX-11 result status is present on every OBX segment

A full fix report is printed before sending so you can see exactly what changed.

**From the editor:**
```
editor> import captured_vitals.hl7
editor> sanitize
editor> show 1
editor> save captured_fixed.hl7
```

---

## Message Editor

Build, modify, and paste HL7 messages interactively without editing files manually.

```cmd
REM Launch standalone editor
hl7-security-tester.exe -file messages.hl7 -edit

REM Or from inside the interactive shell
hl7sec> edit
```

### Editor Commands

**Viewing**
```
list              List all messages with summary
show [n]          Show all segments of message n
validate [n]      Check HL7 structural validity
```

**Creating / Pasting**
```
new               Create a blank ADT^A01 template
paste [n]         Paste HL7 copied from your real system
dup <n>           Duplicate message n with new ID and timestamp
import <file>     Append messages from another .hl7 file
```

**Editing**
```
add-seg <n> <SEG>              Append a segment to message n
add-seg <n> after <s> <SEG>   Insert after segment number s
del-seg <n> <s>               Delete segment s from message n
edit <n> <s>                  Interactively edit fields of segment s
set <n> <s> <f> <value>       Set field f of segment s directly
```

**Managing**
```
sanitize [n]      Fix ACK-blocking issues (all messages or just n)
save [path]       Save all messages to file
export <n> <path> Export single message to its own file
done              Return to main shell
```

**Paste example — loading a real captured message:**
```
editor> paste
  > MSH|^~\&|REALAPP|REALFAC|RECV|RECV|20240315150000||ORU^R01|MSG999|P|2.5
  > PID|1||MRN99999^^^HOSP||SMITH^JANE||19751220|F
  > OBX|1|NM|WBC^WHITE BLOOD COUNT||5.8|10*3/uL|4.5-11.0|N|||F
  > END
```

**Adding OBX segments:**
```
editor> add-seg 1 OBX|1|NM|WBC^WHITE BLOOD COUNT||7.2|10*3/uL|4.5-11.0|N|||F
editor> add-seg 1 OBX|2|NM|RBC^RED BLOOD CELLS||4.5|M/uL|4.2-5.4|N|||F
editor> save
```

---

## PCAP Analyser

Extracts HL7 messages directly from a Wireshark or tcpdump network capture file.
No connection to the receiver needed. Supports `.pcap` and `.pcapng` formats.
Pure Go — no Wireshark installation, no libpcap, no Python required.

```cmd
REM Extract and display messages from a capture
hl7-security-tester.exe -pcap capture.pcap

REM Extract and save to a file for immediate use in testing
hl7-security-tester.exe -pcap capture.pcap -pcap-out extracted.hl7

REM Then test with the real extracted messages
hl7-security-tester.exe -host 172.31.1.213 -port 2451 -tls-auto -file extracted.hl7
```

**What the output shows:**
- Total packets scanned and HL7 packets identified
- Communication flow map — who is talking to whom, how many messages, which types
- All unique IP endpoints observed on the clinical network
- Per-message detail: timestamp, type, ID, sending app, PHI fields detected

**Typical workflow with a Wireshark capture:**
1. Run Wireshark on any machine on the clinical network (or use a span port)
2. Save the capture as `.pcap` or `.pcapng`
3. Run: `hl7-security-tester.exe -pcap capture.pcap -pcap-out real_messages.hl7`
4. Use `-file real_messages.hl7` with any other test flags

---

## HL7 Port Scanner

Scans a host or network range to discover HL7 MLLP listeners you may not know
exist. Confirms each open port is actually an HL7 receiver by running an MLLP probe.

```cmd
REM Scan a single host
hl7-security-tester.exe -scan 172.31.1.213

REM Scan a subnet
hl7-security-tester.exe -scan 172.31.0.0/24

REM Scan with TLS auto-detection
hl7-security-tester.exe -scan 172.31.0.0/24 -tls-auto

REM Custom ports
hl7-security-tester.exe -scan 172.31.0.0/24 -scan-ports 2575,2576,6661,9090
```

Default ports probed: `2575`, `2576`, `6661`, `6662`, `8080`, `8443`, `8888`, `9090`

---

## Fuzzer

Load a captured HL7 file and automatically fuzz field values while sending
live to the target. Identifies how the receiver handles malformed, boundary,
and malicious input.

```cmd
hl7-security-tester.exe -fuzz captured_vitals.hl7 ^
  -host 10.0.0.5 -port 2575 -tls-auto ^
  -fuzz-sending-app HL7SECTEST ^
  -fuzz-sending-facility PENTEST ^
  -fuzz-tag SECTEST ^
  -fuzz-delay 0 ^
  -fuzz-iter 500 ^
  -fuzz-out results.csv
```

### Fuzzer Flags

| Flag | Default | Description |
|---|---|---|
| `-fuzz` | | Path to captured HL7 file to fuzz |
| `-fuzz-iter` | `100` | Number of fuzz iterations |
| `-fuzz-delay` | `100` | Milliseconds between sends. Use `0` for maximum speed. |
| `-fuzz-strategy` | `all` | Strategies: `boundary`, `injection`, `format`, `random`, `overflow`, `encoding`, `all` |
| `-fuzz-seg` | | Only fuzz this segment type (e.g. `OBX`, `PID`) |
| `-fuzz-field` | `0` | Only fuzz this field number. `0` = all fields. |
| `-fuzz-out` | | Save results to this CSV file |
| `-fuzz-stop-on-crash` | `false` | Stop if server stops responding |
| `-fuzz-tag` | `SECTEST` | Prefix embedded in every fuzz message ID (MSH-10) |
| `-fuzz-sending-app` | | Override MSH-3 on all fuzz messages to tag them in receiver logs |
| `-fuzz-sending-facility` | | Override MSH-4 on all fuzz messages |

### Fuzz Strategies

| Strategy | What it sends |
|---|---|
| `boundary` | Empty values, 65535-char strings, impossible dates, max integers, `NaN`, `Inf`, null bytes |
| `injection` | SQL `DROP TABLE`, `UNION SELECT`, `xp_cmdshell`, shell `$(whoami)`, XSS, LDAP injection, `\r` segment injection |
| `format` | `%s%s%s`, `%n`, `{{7*7}}`, `${7*7}`, Unicode null, right-to-left override, format strings |
| `random` | Bit flips, duplication, truncation, random same-length replacement |
| `overflow` | 256 / 512 / 1024 / 4096 / 65535 / 131072 byte payloads |
| `encoding` | HL7 escape sequences, overlong UTF-8, URL encoding, HTML entities, zero-width spaces |

### Tagging Fuzz Messages

The `-fuzz-sending-app` and `-fuzz-tag` flags mark every tool message in the
receiver's logs so they are instantly distinguishable from real device messages
without touching any clinical data:

| Field | Real Device | Your Tool |
|---|---|---|
| MSH-3 | `Sending application` | `HL7SECTEST` |
| MSH-4 | `Sending facility` | `PENTEST` |
| MSH-10 | `5074946058641026799` | `SECTEST000042` |

The tagging logic has safety guards — it never modifies deliberately malformed
MSH segments (no field separators, wrong encoding characters) so injection and
malformed test payloads are preserved exactly as intended.

### Anomaly Flags in Fuzz Output

| Flag | Meaning |
|---|---|
| `⚠ AA on injection payload` | Server accepted a clearly malicious value |
| `⚠ ERROR LEAKS: Exception` | Error response reveals internal stack trace |
| `⚠ REFLECTED in response` | Payload echoed back — possible injection vector |
| `⚠ SLOW 12.3s` | Server hung processing the payload |
| `⚠ EMPTY response` | Server sent nothing back |

---

## Interactive Shell

```cmd
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -file messages.hl7 -interactive
```

| Command | Description |
|---|---|
| `list` | List loaded messages |
| `parse <n>` | Show parsed fields of message n |
| `connect` | Open a persistent connection |
| `disconnect` | Close the connection |
| `send <n>` | Send message n and display the response |
| `send-raw <file>` | Send raw file contents as HL7 |
| `replay` | Run replay attack test |
| `timestamp` | Run timestamp replay test |
| `flood <n>` | Connection flood with n connections |
| `oversize` | Send an oversized message |
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
| `CRITICAL` | Immediate risk — plaintext PHI, no authentication, replays accepted, patient data exposed |
| `HIGH` | Significant risk — deprecated TLS, no rate limiting, stale timestamps accepted, PHI in errors |
| `MEDIUM` | Moderate risk — weak input validation, missing size limits, weak audit trail |
| `LOW` | Minor issues |
| `INFO` | Informational — no action required |
| `PASS` | Test passed |

---

## Troubleshooting

**"Authentication failed" on connect**
The receiver is rejecting your MSH identity. Use:
```cmd
-msh-sending-app "ExactAppName" -msh-receiving-app "ExactReceiverName"
```

**"i/o timeout" / no ACK received**
The message was sent but the receiver did not respond in time.
```cmd
-ack-timeout 120s          # increase wait time
-no-response               # skip waiting entirely (for broadcast-only devices)
```

**"EOF" / connection dropped**
The receiver closed the connection immediately. Likely causes:
1. Wrong MSH sending app/facility — use `-msh-sending-app`
2. Structural issues in the message — use `-sanitize`
3. Pre-auth challenge expected — use `-pre-auth`

**"read error: 0 bytes from transport stream" on receiver**
MLLP framing issue. Use `-sanitize` to normalize line endings and fix MSH fields.

**Windows SmartScreen blocks the .exe**
Right-click → Properties → check **Unblock** → OK.
Or run from an elevated Command Prompt.

**Probe passes but security tests fail to connect**
Use `-skip-probe` and run tests directly — the probe uses a simple ADT^A01 which
may be accepted when your real message file has issues. Run with `-sanitize` too.

---

## Common Workflows

**Discover HL7 listeners on an unknown network:**
```cmd
hl7-security-tester.exe -scan 172.31.0.0/24
hl7-security-tester.exe -scan 172.31.0.0/24 -tls-auto
```

**Extract real messages from a network capture then test with them:**
```cmd
hl7-security-tester.exe -pcap hospital_traffic.pcap -pcap-out real_messages.hl7
hl7-security-tester.exe -host 172.31.1.213 -port 2451 -tls-auto ^
  -file real_messages.hl7 -sanitize
```

**First run against a new receiver:**
```cmd
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto -probe
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto -file sample_messages.hl7 -debug
```

**Captured message not getting ACK:**
```cmd
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto ^
  -file captured_vitals.hl7 -sanitize -sanitize-version 2.6 ^
  -msh-sending-app "Sending application" -no-response
```

**Full assessment with JSON report:**
```cmd
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto ^
  -file sample_messages.hl7 -tests all ^
  -output json -out-file report.json
```

**Fuzz OBX values only (for ventilator/patient monitor data):**
```cmd
hl7-security-tester.exe -fuzz captured_vitals.hl7 ^
  -host 10.0.0.5 -port 2575 -tls-auto ^
  -fuzz-seg OBX -fuzz-field 5 ^
  -fuzz-strategy boundary,injection ^
  -fuzz-sending-app HL7SECTEST -fuzz-tag FUZZ ^
  -fuzz-delay 10 -fuzz-iter 300 -fuzz-out obx_results.csv
```

**Replay and DoS tests only:**
```cmd
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto ^
  -file sample_messages.hl7 ^
  -tests replay,timestamp,flood,oversize,slow
```

**Increase oversized message test beyond 10 MB:**
```cmd
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto ^
  -file sample_messages.hl7 -tests oversize -oversize-mb 50
```

---

## HL7 Version Detection

The HL7 version is always in **MSH-12** — the 12th pipe-delimited field:

```
MSH|^~\&|APP|FAC|RECV|RECV|20240315||ORU^R01|MSG001|P|2.6
  1   2    3    4    5    6     7       8    9       10   11 12
```

Field 12 = `2.6` is the version. Your captured message is **HL7 v2.6** which is
why it includes SFT and UAC segments — use `-sanitize-version 2.6` to preserve
this when sanitizing, or `2.5` to downgrade for receivers that reject 2.6.

---

## Legal & Ethical Notice

This tool is for **authorized security assessments only**. Always obtain written
permission before testing systems that handle Protected Health Information (PHI).
Unauthorized testing of healthcare systems may violate HIPAA and computer fraud laws.
