# HL7 Security Tester

A Go-based bidirectional HL7 v2.x security assessment tool for testing HIPAA compliance and PHI protection in HL7 receivers. Includes a built-in message editor for building and modifying test messages from scratch or from real system captures.

---

## What It Tests

| Category | Tests |
|---|---|
| **Eavesdropping** | Plaintext connection rejection, TLS enforcement |
| **TLS Quality** | Version checks (TLS 1.0/1.1 rejected, TLS 1.2/1.3 accepted), cipher suite |
| **Certificates** | Expiry, hostname match, key usage |
| **Replay Attacks** | Duplicate message ID detection, stale timestamp detection (48h window) |
| **Denial of Service** | Connection flood / rate limiting, oversized message (10 MB), slow client / idle timeout, malformed input (7 variants) |
| **PHI Exposure** | PHI fields echoed in ACK responses, PHI field inventory in loaded messages |

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

---

## Quick Start

### Full assessment — no TLS

```bash
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -file messages.hl7
```

### Full assessment — TLS, no certificates needed

```bash
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto -file messages.hl7
```

### Full assessment — TLS with CA verification

```bash
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls -ca ca.pem -file messages.hl7
```

---

## All Flags

### BASIC

| Flag | Default | Description |
|---|---|---|
| `-host` | `localhost` | Target HL7 receiver hostname or IP |
| `-port` | `2575` | Target port |
| `-file` | | HL7 message file to send |
| `-tests` | `all` | Comma-separated tests to run |
| `-debug` | `false` | Verbose debug logging |

### TLS

| Flag | Description |
|---|---|
| `-tls` | Use TLS with full certificate verification. Uses system roots unless `-ca` is provided. |
| `-tls-auto` | **Zero-config TLS.** No certs needed. Connects and encrypts automatically, accepting any server certificate. Use this when you want TLS without hunting for cert files. |
| `-ca` | CA cert (PEM) to verify the server. When used with `-tls-auto`, enables full chain validation instead of accept-any. |
| `-cert` | Client certificate (PEM). Only needed when the **server** requires mutual TLS (mTLS). Rare in HL7 environments. |
| `-key` | Client key (PEM). Required only alongside `-cert`. |
| `-skip-verify` | Disable cert verification entirely. INSECURE — used internally by TLS tests. |

**TLS mode quick reference:**

| Scenario | Flags |
|---|---|
| No TLS (plaintext) | *(no TLS flags)* |
| TLS, no certs | `-tls-auto` |
| TLS + verify server | `-tls -ca ca.pem` |
| TLS + client cert (mTLS) | `-tls-auto -cert client.pem -key client.key` |

### TIMEOUTS

| Flag | Default | Description |
|---|---|---|
| `-timeout` | `10s` | Connection timeout |
| `-ack-timeout` | `60s` | How long to wait for an ACK. Accepts any Go duration: `30s`, `2m`, `120s`. |
| `-read-timeout` | | Alias for `-ack-timeout` |
| `-no-response` | `false` | Do not wait for an ACK — fire and forget. Use when the receiver never ACKs. |

**Timeout troubleshooting:**

```bash
# Receiver is slow to ACK
-ack-timeout 120s

# Receiver never sends an ACK
-no-response
```

### DOS TUNING

| Flag | Default | Description |
|---|---|---|
| `-flood-conns` | `50` | Number of connections for flood test |
| `-flood-concurrency` | `10` | Concurrent connections during flood test |
| `-slow-hold` | `10s` | How long to hold an idle connection in slow-client test |

### OUTPUT

| Flag | Default | Description |
|---|---|---|
| `-output` | `text` | Output format: `text` or `json` |
| `-out-file` | stdout | Write report to this file |

### MODES

| Flag | Description |
|---|---|
| `-interactive` | Launch interactive shell for manual testing |
| `-edit` | Launch the message editor (add segments, paste real HL7, save) |

---

## Available Tests

| Name | What it tests |
|---|---|
| `encryption` | Plaintext rejection, PHI echoed in ACK |
| `tls` | TLS 1.0/1.1 rejected, TLS 1.2/1.3 accepted |
| `cert` | Certificate expiry, hostname match, key usage |
| `replay` | Duplicate message ID detection |
| `timestamp` | Stale 48-hour-old timestamp acceptance |
| `flood` | Connection rate limiting |
| `oversize` | 10 MB message handling |
| `malformed` | 7 variants of structurally invalid input |
| `slow` | Idle connection timeout enforcement |
| `phi` | PHI fields echoed in ACK responses |

```bash
-tests all
-tests replay,timestamp
-tests encryption,tls,cert
-tests flood,oversize,malformed,slow
```

---

## Message Editor

The built-in editor lets you build, modify, and paste HL7 messages without editing files manually.

### Launch

```bash
# Standalone — loads and saves to your file
hl7-security-tester.exe -file messages.hl7 -edit

# Or from inside the interactive shell
hl7sec> edit
```

### Editor Commands

**Viewing**

| Command | Description |
|---|---|
| `list` | List all messages with summary |
| `show [n]` | Show all segments of message n |
| `validate [n]` | Check HL7 structural validity |

**Creating / Pasting**

| Command | Description |
|---|---|
| `new` | Create a blank ADT^A01 template |
| `paste [n]` | Paste HL7 from your real system (replaces message n if given) |
| `dup <n>` | Duplicate message n with a new ID and timestamp |
| `import <file>` | Append messages from another .hl7 file |

**Editing**

| Command | Description |
|---|---|
| `add-seg <n> <SEG>` | Append a segment to message n |
| `add-seg <n> after <s> <SEG>` | Insert segment after segment s |
| `del-seg <n> <s>` | Delete segment s from message n |
| `edit <n> <s>` | Interactively edit fields of segment s |
| `set <n> <s> <f> <value>` | Directly set field f of segment s |

**Managing**

| Command | Description |
|---|---|
| `del-msg <n>` | Delete entire message n |
| `save [path]` | Save all messages (default: original file) |
| `export <n> <path>` | Export a single message to its own file |
| `done` | Return to main shell |

### Pasting Real HL7 from Your System

Copy a message straight from your live app's logs or monitoring tool:

```
editor> paste
  > MSH|^~\&|REALAPP|REALFAC|RECV|RECV|20240315150000||ORU^R01|MSG999|P|2.5
  > PID|1||MRN99999^^^HOSP||SMITH^JANE||19751220|F
  > OBR|1|||CBC^COMPLETE BLOOD COUNT
  > OBX|1|NM|WBC^WHITE BLOOD COUNT||5.8|10*3/uL|4.5-11.0|N|||F
  > OBX|2|NM|RBC^RED BLOOD CELLS||4.2|M/uL|3.8-5.1|N|||F
  > END
```

Type `END` or leave a blank line to finish. The tool validates the message and shows a summary.

### Adding OBX Segments to an Existing Message

```
editor> show 1
editor> add-seg 1 OBX|1|NM|WBC^WHITE BLOOD COUNT||7.2|10*3/uL|4.5-11.0|N|||F
editor> add-seg 1 OBX|2|NM|RBC^RED BLOOD CELLS||4.5|M/uL|4.2-5.4|N|||F
editor> add-seg 1 NTE|1|L|Patient fasting 8 hours prior to draw
editor> save
```

### Inserting at a Specific Position

```
editor> show 1                              # note segment numbers
editor> add-seg 1 after 3 DG1|1||I10^HYPERTENSION^ICD10
```

### Editing a Specific Field

```
editor> set 1 3 5 SMITH^JOHN^A             # message 1, segment 3, field 5
editor> edit 1 3                            # interactive field picker
```

---

## Interactive Shell

```bash
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -file messages.hl7 -interactive
```

| Command | Description |
|---|---|
| `list` | List loaded messages |
| `parse <n>` | Show parsed fields of message n |
| `connect` | Open a persistent connection |
| `disconnect` | Close the connection |
| `send <n>` | Send message n and show the response |
| `send-raw <file>` | Send raw file contents as HL7 |
| `replay` | Replay attack test |
| `timestamp` | Timestamp replay test |
| `flood <n>` | Connection flood with n connections |
| `oversize` | Send a 10 MB message |
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
| `CRITICAL` | Immediate risk — plaintext PHI, expired cert, replays accepted |
| `HIGH` | Significant risk — deprecated TLS, no rate limiting, stale timestamps accepted |
| `MEDIUM` | Moderate risk — weak input validation, missing size limits |
| `LOW` | Minor issues |
| `INFO` | Informational |
| `PASS` | Test passed |

---

## Common Workflows

**First run against a new receiver:**
```bash
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto -file testdata/sample_messages.hl7 -debug
```

**Receiver is slow to ACK:**
```bash
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto -file messages.hl7 -ack-timeout 120s
```

**Receiver never ACKs:**
```bash
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto -file messages.hl7 -no-response
```

**Build test messages from a real system capture:**
```bash
hl7-security-tester.exe -file messages.hl7 -edit
```

**JSON audit report:**
```bash
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto -file messages.hl7 -output json -out-file report.json
```

**Replay and DoS tests only:**
```bash
hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto -file messages.hl7 -tests replay,timestamp,flood,oversize,slow
```

---

## Architecture

```
cmd/main.go                  — CLI, flags, interactive shell, editor mode
pkg/hl7/message.go           — HL7 v2.x parser, MLLP framing, PHI scanner
pkg/transport/client.go      — TCP/TLS connection, bidirectional send/receive
pkg/security/tests.go        — All security test implementations
pkg/reporter/report.go       — Text and JSON report generation
pkg/editor/editor.go         — Interactive message editor
testdata/sample_messages.hl7 — Sample ADT, ORU, and RDE messages
```

---

## Legal & Ethical Notice

This tool is intended for **authorized security assessments only**. Always obtain written permission before testing systems that handle Protected Health Information (PHI). Unauthorized testing of healthcare systems may violate HIPAA and computer fraud laws.

---

## Top HL7 Security Risks & Tests

Based on documented real-world attacks (Black Hat 2018, ERNW 2020, TXOne 2026) and HIPAA Technical Safeguard requirements. Run these with `-tests all` or individually.

### Risk 1 — Segment Injection (`-tests seginject`)
**Severity: CRITICAL**

Documented at Black Hat 2018 ("Pestilential Protocol") and ERNW 2020 (patient monitor research). An attacker embeds `\r` characters inside HL7 field values to inject rogue segments — fake medication orders (`RXE`), diagnoses (`DG1`), a second `MSH`, or custom Z-segments claiming elevated privileges. Vulnerable receivers process the injected segments as legitimate data.

Tests: RXE injection via PID name, DG1 injection via OBX value, second MSH injection, Z-segment privilege escalation.

### Risk 2 — Field Tampering / Data Integrity (`-tests tampering`)
**Severity: CRITICAL / HIGH**

HL7 v2 has no native message signing or integrity verification. An attacker positioned on the network can silently modify medication dosages, lab results, allergy records, or patient demographics in transit. The receiver has no way to detect the change. This is the attack described at Black Hat 2018 where researchers changed a morphine dosage from 1mg to 99mg in an intercepted HL7 message.

Tests: impossible DOB (year 2999), extreme lab result (WBC 999999), lethal medication dose (99999mg morphine), allergy segment erasure, negative age boundary check.

### Risk 3 — SQL / Command / Script Injection (`-tests injection`)
**Severity: HIGH / CRITICAL**

Many HL7 receivers write patient fields (name, MRN, notes) directly to SQL databases without sanitisation. Patient-facing fields are common injection vectors because they accept free text. If the receiver is vulnerable, an attacker can exfiltrate data, modify records, or execute OS commands.

Tests: SQL DROP TABLE in PID-5, SQL OR-injection in MRN, UNION SELECT in OBX value, xp_cmdshell in NTE notes, shell command substitution in MSH-3, XSS in patient name, LDAP injection.

### Risk 4 — Unauthorized Sender / Spoofing (`-tests spoof`)
**Severity: CRITICAL**

MLLP has no built-in sender authentication. Any machine with network access to the HL7 port can claim to be any sending application (HIS, LIS, PHARMACY, ADMIN). This is analogous to Telnet/FTP — the receiver has no way to verify the identity of the sender without additional controls (IP allowlisting, mutual TLS, or application-layer auth).

Tests: Messages claiming to be HIS, ADT, LIS, PHARMACY, EHR, ADMIN, SUPERUSER, ROOT.

### Risk 5 — Patient Record Enumeration (`-tests enum`)
**Severity: MEDIUM / CRITICAL**

Sending `QRY^A19` patient query messages with sequential or guessed MRNs. A vulnerable receiver may: (a) return patient data without authentication, or (b) return different ACK codes for valid vs invalid MRNs — allowing an attacker to determine which patient records exist (oracle attack).

Tests: Unauthenticated QRY^A19 queries, differential ACK response analysis across valid/invalid MRNs.

### Risk 6 — Information Leakage in Error Responses (`-tests errleakage`)
**Severity: HIGH**

Some HL7 receivers echo stack traces, database error messages, file paths, or connection strings in the MSA-3 error text or ERR segments when a message fails. This reveals system architecture to an attacker and may expose credentials.

Tests: Invalid message type, oversized field, invalid version number, null MRN — each inspects the NACK for stack traces, SQL errors, file paths, and DB connection strings.

### Risk 7 — Audit Trail Weakness (`-tests audit`)
**Severity: MEDIUM**

HIPAA requires a complete audit log of all HL7 transactions. Systems without proper per-message audit writes may process messages extremely fast with no variance — detectable via response timing analysis. Systems that accept duplicate message IDs without cross-checking may also lack audit persistence.

Tests: Burst of 10 messages with response timing analysis, duplicate ID acceptance rate.

### Risk 8 — PHI Leakage in NACK Responses (`-tests nackleak`)
**Severity: HIGH**

Distinct from the existing PHI-in-ACK test. This specifically checks whether a rejected message's NACK echoes patient identifiers (MRN, name, SSN) in the error text. Even when a message is rejected, the PHI sent in the original message may be reflected back — exposed to anyone intercepting the channel.

Tests: Sends message with distinctive canary values (MRN, name, SSN) and triggers a rejection, then inspects the NACK for the canary values.

---

## Running the Advanced Tests

```bash
# All tests including advanced
hl7-security-tester.exe -host 10.0.0.5 -port 2451 -tls-auto -file messages.hl7 -tests all

# Advanced tests only
hl7-security-tester.exe -host 10.0.0.5 -port 2451 -tls-auto -file messages.hl7 \
  -tests seginject,tampering,injection,spoof,enum,errleakage,audit,nackleak

# Single advanced test
hl7-security-tester.exe -host 10.0.0.5 -port 2451 -tls-auto -file messages.hl7 -tests injection
```
