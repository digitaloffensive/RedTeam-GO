# HL7 Vulnerable Listener

A deliberately vulnerable HL7 v2.x MLLP listener designed as a **safe, controlled test target** for the HL7 Security Tester tool. It intentionally implements every major HL7 security weakness so you can verify your security tool detects them correctly — and run in fixed mode to confirm it reports PASS when the issues are resolved.

---

> ⚠️ **WARNING: FOR TESTING ONLY**
> This listener is intentionally insecure. It echoes patient data in error messages, accepts injection payloads, has no authentication, and exposes internal stack traces with fake database credentials. **Never deploy this on a production network or any system accessible to real patients or clinical systems.**

---

## What It Tests

The listener implements 12 deliberate vulnerabilities, each directly mappable to a finding in the HL7 Security Tester:

| # | Vulnerability | Security Tester Flag | Severity |
|---|---|---|---|
| 1 | Plaintext transport — no TLS enforced | `-tests encryption` | CRITICAL |
| 2 | No sender authentication — any MSH-3/4 accepted | `-tests spoof` | CRITICAL |
| 3 | No timestamp validation — unlimited replay window | `-tests timestamp` | HIGH |
| 4 | No duplicate message ID detection | `-tests replay` | HIGH |
| 5 | No input sanitisation — injection payloads accepted | `-tests injection` | HIGH |
| 6 | No message size limits — oversized messages accepted | `-tests oversize` | HIGH |
| 7 | No connection rate limiting — flood attacks possible | `-tests flood` | HIGH |
| 8 | No idle connection timeout — slow client attacks | `-tests slow` | MEDIUM |
| 9 | PHI echoed in error responses | `-tests nackleak` | HIGH |
| 10 | Stack traces + DB credentials in error messages | `-tests errleakage` | HIGH |
| 11 | Patient records returned to unauthenticated queries | `-tests enum` | CRITICAL |
| 12 | No HL7 version validation — any version accepted | `-tests malformed` | MEDIUM |

---

## Installation

The binary is statically linked — **no dependencies, no runtime, no Go installation needed** on the Linux machine.

```bash
# Copy the binary to your Linux box
scp hl7-vulnerable-listener-linux-amd64 user@192.168.1.x:/opt/hl7-listener/

# Make it executable
chmod +x hl7-vulnerable-listener-linux-amd64

# Run it
./hl7-vulnerable-listener-linux-amd64
```

---

## Quick Start

### Run fully vulnerable (default)
Tests all 12 security findings — every test in the Security Tester should report FAIL:

```bash
./hl7-vulnerable-listener-linux-amd64 -port 2575
```

### Run in fixed mode
All vulnerabilities remediated — every test should report PASS:

```bash
./hl7-vulnerable-listener-linux-amd64 -port 2576 -mode fixed
```

### Run both side by side
Point your security tester at 2575 to see failures, then at 2576 to see passes:

```bash
./hl7-vulnerable-listener-linux-amd64 -port 2575 -log vuln.log &
./hl7-vulnerable-listener-linux-amd64 -port 2576 -mode fixed -log fixed.log &
```

---

## All Flags

| Flag | Default | Description |
|---|---|---|
| `-port` | `2575` | TCP port to listen on |
| `-mode` | `vulnerable` | `vulnerable`, `fixed`, or `custom` |
| `-log` | `hl7-listener.log` | Audit log file (JSON, one entry per line) |
| `-verbose` | `true` | Print each message to stdout as it arrives |

### Individual vulnerability flags (use with `-mode custom`)

| Flag | Default | Controls |
|---|---|---|
| `-no-tls` | `true` | Accept plaintext connections |
| `-no-auth` | `true` | Accept any sending application |
| `-no-timestamp` | `true` | Accept messages with any timestamp age |
| `-no-duplicate` | `true` | Accept duplicate message IDs |
| `-no-sanitise` | `true` | Accept injection payloads |
| `-no-size-limit` | `true` | Accept messages of any size |
| `-no-rate-limit` | `true` | Accept unlimited connections |
| `-no-idle-timeout` | `true` | Never close idle connections |
| `-echo-phi` | `true` | Echo patient data in error responses |
| `-stack-trace` | `true` | Include stack traces in errors |
| `-enum-patients` | `true` | Return patient records to unauthenticated queries |
| `-no-version-check` | `true` | Accept any HL7 version string |

---

## Modes

### `vulnerable` — All weaknesses enabled
Every test in the HL7 Security Tester should return FAIL or a finding. Use this to validate your tool is detecting everything correctly.

### `fixed` — All weaknesses remediated
Every test should return PASS. Use this to confirm your tool correctly identifies secure behaviour and does not produce false positives.

Fixed mode enforces:
- Sender allowlist (accepts: `Sending application`, `HL7PROBE`, `TESTSYSTEM`, `LAB`, `ADT`)
- Message timestamp max age: 10 minutes
- Duplicate message ID rejection (rolling 24h window)
- Injection payload detection and rejection
- Message size limit: 1 MB
- Connection rate limit: 20 connections per minute per IP
- Idle connection timeout: 30 seconds
- Generic error messages (no PHI, no stack traces)
- QRY queries require authentication (always rejected)
- HL7 version must begin with `2.`

### `custom` — Pick your vulnerabilities
Enable specific vulnerabilities for targeted testing. Useful for demonstrating individual findings to a client one at a time.

```bash
# Vulnerable only to replay attacks (timestamp + duplicate ID)
./hl7-vulnerable-listener-linux-amd64 -port 2577 -mode custom \
  -no-timestamp=true -no-duplicate=true \
  -no-auth=false -no-sanitise=false

# Vulnerable only to injection
./hl7-vulnerable-listener-linux-amd64 -port 2578 -mode custom \
  -no-sanitise=true \
  -no-timestamp=false -no-duplicate=false

# Vulnerable only to PHI leakage in errors
./hl7-vulnerable-listener-linux-amd64 -port 2579 -mode custom \
  -echo-phi=true -stack-trace=true \
  -no-auth=false -no-timestamp=false
```

---

## Running the Security Tester Against It

### Full test — all findings (against vulnerable listener)

```cmd
hl7-security-tester.exe -host 192.168.1.x -port 2575 ^
  -file sample_messages.hl7 ^
  -tests all ^
  -skip-probe ^
  -output text
```

### Full test — verify all pass (against fixed listener)

```cmd
hl7-security-tester.exe -host 192.168.1.x -port 2576 ^
  -file sample_messages.hl7 ^
  -tests all ^
  -skip-probe
```

### Test a specific vulnerability in isolation

```bash
# Start listener vulnerable only to replay
./hl7-vulnerable-listener-linux-amd64 -port 2577 -mode custom \
  -no-timestamp=true -no-duplicate=true \
  -no-auth=false -no-sanitise=false -no-size-limit=false
```

```cmd
# Test only replay against it
hl7-security-tester.exe -host 192.168.1.x -port 2577 ^
  -file sample_messages.hl7 -tests replay,timestamp
```

### Fuzz the vulnerable listener

```cmd
hl7-security-tester.exe -fuzz sample_messages.hl7 ^
  -host 192.168.1.x -port 2575 ^
  -fuzz-sending-app HL7SECTEST ^
  -fuzz-tag FUZZ ^
  -fuzz-delay 0 ^
  -fuzz-iter 500 ^
  -fuzz-out fuzz-results.csv
```

---

## What You Should See

When running the Security Tester against the **vulnerable** listener, expect:

```
  ✗ [CRITICAL] EncryptionRequired   Server accepts UNENCRYPTED HL7 messages
  ✗ [HIGH]     TimestampReplay      Server accepted message with 48-hour-old timestamp
  ✗ [HIGH]     ReplayAttack         Server ACCEPTED replayed message — no duplicate detection
  ✗ [HIGH]     ConnectionFlood      Server accepted all flood connections — no rate limiting
  ✗ [HIGH]     OversizedMessage     Server processed a 10 MB message without error
  ✗ [HIGH]     NACKPHILeak          NACK response echoes patient PHI fields
  ✗ [HIGH]     ErrorLeakage         Error response leaks stack trace and DB credentials
  ✗ [CRITICAL] UnauthorizedSender   Server accepts messages from ANY sender
  ✗ [CRITICAL] Enum-DataLeak        Server returned patient PID data to unauthenticated query
  ...
```

Against the **fixed** listener, every test should show:

```
  ✓ [PASS]     TimestampReplay      Server rejected message with stale timestamp (48h old)
  ✓ [PASS]     ReplayAttack         Server rejected replayed message (duplicate detection working)
  ✓ [PASS]     ConnectionFlood      Server rate-limited connections (>50% refused)
  ...
```

---

## Audit Log

Every connection, message, and rejection is written to the log file in JSON format:

```json
{"time":"2026-05-19T18:20:00Z","event":"CONNECT","remote":"10.0.0.5:49231","detail":"New connection"}
{"time":"2026-05-19T18:20:00Z","event":"MESSAGE","remote":"10.0.0.5:49231","detail":"Type=ADT^A01 ID=MSG001 Segments=4 Size=312 bytes"}
{"time":"2026-05-19T18:20:00Z","event":"ACCEPT","remote":"10.0.0.5:49231","detail":"Message accepted: MSG001"}
{"time":"2026-05-19T18:20:01Z","event":"REJECT","remote":"10.0.0.5:49231","detail":"Duplicate message ID: MSG001"}
{"time":"2026-05-19T18:20:02Z","event":"SECURITY","remote":"10.0.0.5:49231","detail":"Injection payload detected: \"DROP TABLE\""}
```

Tail the log in real time while testing:

```bash
tail -f hl7-listener.log | python3 -m json.tool
```

---

## Building From Source

Requires Go 1.21+.

```bash
# Build for current platform
go build -o hl7-vulnerable-listener .

# Build for Linux (from Mac or Windows)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o hl7-vulnerable-listener-linux-amd64 .

# Or use the Makefile
make build
make build-linux
make run          # vulnerable on port 2575
make run-fixed    # fixed on port 2576
make run-both     # both simultaneously
```

---

## Running as a systemd Service (Linux)

To keep it running in the background across reboots:

```bash
# Create service file
sudo tee /etc/systemd/system/hl7-listener.service << EOF
[Unit]
Description=HL7 Vulnerable Listener (Security Testing)
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/opt/hl7-listener/hl7-vulnerable-listener-linux-amd64 -port 2575 -log /var/log/hl7-listener.log
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable hl7-listener
sudo systemctl start hl7-listener
sudo systemctl status hl7-listener
```

---

## Firewall

Only allow access from your testing machine — never expose this to the open internet:

```bash
# UFW
sudo ufw allow from 192.168.1.x to any port 2575
sudo ufw allow from 192.168.1.x to any port 2576

# iptables
sudo iptables -A INPUT -p tcp --dport 2575 -s 192.168.1.x -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 2575 -j DROP
```

---

## Architecture

The entire listener is a single Go file (`main.go`, ~800 lines) with no external dependencies. Key components:

```
main.go
├── VulnConfig struct      — 12 boolean vulnerability toggles
├── AllVulnerable()        — returns all-enabled config
├── AllFixed()             — returns all-remediated config
├── Server.Run()           — TCP accept loop with optional rate limiting
├── Server.handleConn()    — per-connection MLLP read/write loop
├── Server.processMessage()— core handler: all 12 vulnerability checks live here
├── Server.buildACK()      — ACK builder with optional PHI echo + stack trace
├── Server.buildQueryResponse() — patient enumeration response (VULN 11)
├── parseHL7()             — minimal HL7 parser (MSH, PID, QRD fields)
├── readMLLP()             — MLLP frame reader with optional size limit
└── wrapMLLP()             — MLLP frame writer
```

Each vulnerability is a clearly commented block in `processMessage()` with the vulnerable code path and the fixed path side by side, making it easy to understand what the fix looks like in practice.

---

## Legal & Ethical Notice

This tool is for **authorized security testing only** in isolated lab environments. Never deploy on a network that carries real Protected Health Information (PHI). The fake patient data (names, MRNs, SSNs) used in responses is entirely synthetic and does not correspond to any real individual.
