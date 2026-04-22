# FileScanner — Sensitive Data Scanner for File Shares

A fast, modular Go tool that recursively scans file shares for sensitive data
(credentials, PII, keys, healthcare data, financial info) and logs all findings
to CSV with file permissions, line numbers, and a redacted content preview.

---

## Features

| Feature | Detail |
|---|---|
| **27 built-in patterns** | Passwords, API keys, AWS keys, SSNs, credit cards, IBAN, PII, HIPAA, certs |
| **Pause / Resume** | Type `p` to pause mid-scan; `r` to resume |
| **Skip folders** | Type `sf archive` to skip any folder matching "archive" |
| **Skip extensions** | Type `se .log` to stop scanning `.log` files dynamically |
| **File permissions** | Logs Readable/Writable/Executable, owner, and Unix mode string |
| **Screenshot capture** | Captures flagged context lines (redacted) as base64 in the CSV |
| **Concurrent scanning** | Configurable worker pool (default 4) |
| **Plugin system** | Add custom behaviour via the `plugin.Plugin` interface |
| **CSV output** | All fields quoted correctly; appends to existing CSV on re-runs |

---

## Quick Start

```bash
# Build
go build -o scanner ./cmd/scanner/

# Scan a share
./scanner /mnt/fileserver/shared

# Multiple shares, custom output
./scanner --out results.csv /data/hr /data/finance /data/ops

# Pre-skip extensions and folders
./scanner --skip-exts .log,.tmp --skip-folders archive,backup /shares

# Scan only specific extensions
./scanner --exts .env,.config,.yml,.json /etc /opt

# More workers, larger file limit
./scanner --workers 8 --maxsize 100 /mnt/nas
```

---

## CSV Output Columns

| Column | Description |
|---|---|
| `ScanDate` | Timestamp of the finding |
| `SharePath` | Root share path that was scanned |
| `Folder` | Parent folder of the file |
| `FileName` | File name |
| `FileExtension` | File extension |
| `PatternName` | Name of the pattern that matched |
| `Severity` | CRITICAL / HIGH / MEDIUM / LOW |
| `LineNumbers` | Comma-separated line numbers that matched |
| `LinePreview` | First matching line (truncated, partially redacted) |
| `Permissions` | e.g. `RW- owner:jsmith mode:-rw-r--r--` |
| `Owner` | File owner username or UID |
| `FileSizeBytes` | File size in bytes |
| `Screenshot_Base64` | Base64-encoded text block of flagged lines with context |

### Decoding a Screenshot

```python
import csv, base64
with open("scan_results.csv") as f:
    for row in csv.DictReader(f):
        if row["Screenshot_Base64"]:
            print(base64.b64decode(row["Screenshot_Base64"]).decode())
            break
```

---

## Interactive Commands

While a scan is running, type commands in the terminal:

```
p / pause     — Pause the scan
r / resume    — Resume
s / status    — Show live counters and current file
sf <name>     — Skip all folders whose path contains <name>
se <ext>      — Skip all files with extension <ext>
q / quit      — Stop and exit
h / help      — Show command list
```

Commands take effect immediately for the next file picked up by workers.

---

## Pattern Categories

- **Credentials**: passwords, API keys, tokens, secrets
- **AWS/Cloud**: AWS access keys, secret keys, Docker/k8s secrets
- **PII**: SSN, credit card, email, phone, date of birth, passport, national ID
- **Financial**: IBAN, BIC/SWIFT, Bitcoin addresses
- **Healthcare**: NHS numbers, ICD codes, HIPAA keywords
- **Infrastructure**: private IPs, internal hostnames, connection strings, JDBC URLs
- **Certificates**: PEM private keys, certificates, SSH host keys

---

## Project Structure

```
filescanner/
├── cmd/
│   └── scanner/
│       └── main.go              ← Entry point, CLI flags, interactive console
├── internal/
│   ├── scanner/
│   │   └── scanner.go           ← Core walk + scan engine
│   ├── patterns/
│   │   └── patterns.go          ← All regex patterns (add new ones here)
│   ├── control/
│   │   └── control.go           ← Pause/resume/skip controller
│   ├── permissions/
│   │   ├── permissions.go       ← File permission detection
│   │   ├── owner_unix.go        ← Unix owner lookup
│   │   └── owner_windows.go     ← Windows stub (extend as needed)
│   ├── screenshot/
│   │   └── screenshot.go        ← Redacted context capture → base64
│   └── output/
│       └── csv.go               ← Thread-safe CSV writer
└── pkg/
    └── plugin/
        ├── plugin.go            ← Plugin interface + Registry
        └── examples/
            └── hashplugin/
                └── hash.go      ← Example: SHA-256 hash logger plugin
```

---

## Adding Patterns

Edit `internal/patterns/patterns.go` and add an entry to the `defs` slice:

```go
{"My Custom Pattern", "Description", `(?i)my_regex_here`, "HIGH"},
```

Severity must be one of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.

---

## Writing a Plugin

Implement the `plugin.Plugin` interface (embed `plugin.NoopPlugin` for defaults):

```go
package myplugin

import (
    "filescanner/internal/output"
    "filescanner/pkg/plugin"
    "fmt"
)

type AlertPlugin struct{ plugin.NoopPlugin }

func (p *AlertPlugin) Name() string { return "alerter" }

func (p *AlertPlugin) OnFinding(ctx *plugin.Context, f *output.Finding) {
    if f.Severity == "CRITICAL" {
        fmt.Printf("[ALERT] CRITICAL finding in %s — %s\n", f.FileName, f.PatternName)
        // Send email, post to Slack, write to SIEM, etc.
    }
}
```

Register it in `cmd/scanner/main.go`:

```go
plugins.Register(&myplugin.AlertPlugin{})
```

### Plugin hooks

| Hook | When called |
|---|---|
| `OnFileStart(ctx)` | Before each file is scanned |
| `OnFinding(ctx, finding)` | For each pattern match found |
| `OnFileEnd(ctx)` | After a file is fully processed |
| `OnScanComplete(files, findings)` | Once, when the scan finishes |

---

## Building for Windows

```bash
GOOS=windows GOARCH=amd64 go build -o scanner.exe ./cmd/scanner/
```

> Note: Windows file owner lookup (`owner_windows.go`) is a stub.
> Full implementation requires `golang.org/x/sys/windows` — add it and extend
> the stub when targeting Windows file shares.

---

## Flags Reference

```
--out string         Output CSV file path (default: scan_YYYYMMDD_HHMMSS.csv)
--workers int        Concurrent scan workers (default: 4)
--maxsize int        Max file size to scan in MB (default: 50)
--exts string        Comma-separated extensions to scan (default: all text)
--skip-exts string   Comma-separated extensions to skip
--skip-folders string Comma-separated folder names/paths to skip
--no-screenshot      Disable base64 screenshot capture
```
