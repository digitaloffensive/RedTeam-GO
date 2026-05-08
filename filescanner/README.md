# FileScanner — Sensitive Data Scanner for File Shares and Local Folders

A fast, modular Go tool that recursively scans network file shares **and local
folders** for sensitive data — credentials, PII, keys, healthcare data, financial
info — and logs all findings to CSV with file permissions, line numbers, owner
information, and a redacted content preview. Results can be exported to a rich
Excel workbook with embedded screenshots, colour-coded severity, and a summary
dashboard.

---

## Features

| Feature | Detail |
|---|---|
| **Dual scan modes** | Network share mode (default) and local folder mode (`--local`) |
| **Local path resolution** | `~` home expansion, relative → absolute conversion, existence validation |
| **27 built-in patterns** | Passwords, API keys, AWS keys, SSNs, credit cards, IBAN, PII, HIPAA, certs |
| **Pause / Resume / Skip** | Live interactive console — pause, resume, skip folders or extensions mid-scan |
| **File permissions** | Logs Readable/Writable/Executable, owner, Unix mode string, and Windows attribute flags |
| **Cross-platform owner lookup** | Linux/macOS: UID → username via syscall; Windows: `GetSecurityInfo` → `LookupAccountSid` → `DOMAIN\Username` |
| **Screenshot capture** | Captures flagged context lines (redacted) as base64 in CSV; renders as embedded images in Excel |
| **Excel export** | `csv_to_excel.py` converts CSV to `.xlsx` with dark-themed code images, severity colouring, and a summary dashboard |
| **Concurrent scanning** | Configurable worker pool (default 4 goroutines) |
| **Plugin system** | Extend with custom hooks via the `plugin.Plugin` interface |
| **CSV output** | Thread-safe writer; appends to existing CSV on re-runs |
| **Vendored dependencies** | `golang.org/x/sys/windows` vendored in `vendor/` — no internet access needed to build |

---

## Quick Start

```bash
# Build (Linux / macOS)
go build -o scanner ./cmd/scanner/

# Build for Windows (cross-compile from any OS)
GOOS=windows GOARCH=amd64 go build -o scanner.exe ./cmd/scanner/

# --- Network share mode (default) ---

# Scan a single share
./scanner /mnt/fileserver/shared

# Multiple shares with a custom output file
./scanner --out results.csv /data/hr /data/finance /data/ops

# Pre-skip extensions and folders at startup
./scanner --skip-exts .log,.tmp --skip-folders archive,backup /shares

# --- Local folder mode (--local) ---

# Scan your home directory
./scanner --local ~/Documents

# Scan multiple local folders, skip dependency directories
./scanner --local --skip-folders node_modules,vendor /home/user/projects

# Scan only specific extensions in a local path
./scanner --local --exts .env,.yml,.config ~/projects

# Relative paths and ~ both work in local mode
./scanner --local . ~/Desktop ../configs

# Windows local folders
scanner.exe --local C:\Users\alice\Documents C:\Projects

# --- Common options ---

# More workers, larger file size limit
./scanner --workers 8 --maxsize 100 /mnt/nas

# Convert CSV output to Excel with embedded screenshots
python3 csv_to_excel.py results.csv
# → produces results.xlsx

# Convert without image rendering (stores decoded text in cell instead)
python3 csv_to_excel.py results.csv --no-images --out report.xlsx
```

---

## Scan Modes

### Network Share Mode (default)

Pass UNC paths or mounted network share paths as arguments. The scanner walks
each path and warns if an argument looks like a local filesystem path (e.g.
`/home/...` or `~/...`) rather than a mounted share.

```bash
./scanner /mnt/fileserver/hr /mnt/fileserver/finance
./scanner \\fileserver\hr \\fileserver\finance   # Windows UNC
```

The banner labels the targets as **Shares** and the finding block shows
`Share :` for each result.

### Local Folder Mode (`--local`)

Pass any local directory paths. The `--local` flag enables:

- **`~` expansion** — `~/Documents` is resolved to the user's home directory on all platforms
- **Relative → absolute conversion** — paths like `.` or `../configs` are expanded against the current working directory
- **Existence validation** — the scanner errors early with a clear message if a path does not exist or is not a directory, rather than silently scanning nothing

```bash
./scanner --local ~/Documents ~/Desktop
./scanner --local /etc /home/user/projects
./scanner --local .                          # current directory
```

The banner labels the targets as **Folders** and the finding block shows
`Folder:` for each result.

> **Tip:** The underlying walk logic is identical for both modes. `--local`
> changes path resolution, validation, and console labelling — not scan
> behaviour. You can use absolute paths without `--local`; the flag is primarily
> useful for `~` expansion, relative path support, and upfront directory validation.

---

## Excel Report

`csv_to_excel.py` converts the scanner CSV into a polished `.xlsx` workbook.

**Requirements:**
```bash
pip install openpyxl pillow
```

**What you get:**

| Sheet | Contents |
|---|---|
| **Summary** | CRITICAL/HIGH/MEDIUM/LOW counts, top files by finding count, pattern breakdown table |
| **Findings** | All CSV columns colour-coded by severity; `Screenshot` column shows a dark-themed code image with flagged lines highlighted in amber |

The screenshot images are rendered from the base64 content captured during
scanning. Each image shows up to 20 matched lines with 2 lines of context above
and below, with credential values partially redacted (first 3 characters +
asterisks).

---

## CSV Output Columns

| Column | Description |
|---|---|
| `ScanDate` | Timestamp of the finding |
| `SharePath` | Root share or local folder path that was scanned |
| `Folder` | Parent folder of the file |
| `FileName` | File name |
| `FileExtension` | File extension |
| `PatternName` | Name of the pattern that matched |
| `Severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| `LineNumbers` | Comma-separated line numbers that matched |
| `LinePreview` | First matching line (truncated, partially redacted) |
| `Permissions` | e.g. `RW- owner:CORP\jsmith mode:-rw-r--r-- attrs:READONLY\|ARCHIVE` |
| `Owner` | File owner — username on Linux/macOS, `DOMAIN\Username` on Windows |
| `FileSizeBytes` | File size in bytes |
| `Screenshot_Base64` | Base64-encoded text block of flagged lines with context |

### Decoding a Screenshot Manually

```python
import csv, base64

with open("scan_results.csv") as f:
    for row in csv.DictReader(f):
        if row["Screenshot_Base64"]:
            print(base64.b64decode(row["Screenshot_Base64"]).decode())
            break
```

---

## Flags Reference

| Flag | Default | Description |
|---|---|---|
| `--local` | `false` | Enable local folder mode: activates `~` expansion, relative path resolution, and directory existence validation |
| `--redact-sensitive` | `false` | Suppress `LinePreview` and `Screenshot` for PHI/SPII patterns. All other fields (path, pattern name, severity, line numbers, permissions) are still logged. See [PHI/SPII Redaction](#phispii-redaction) below. |
| `--out` | `scan_YYYYMMDD_HHMMSS.csv` | Output CSV file path |
| `--workers` | `4` | Number of concurrent scan goroutines |
| `--maxsize` | `50` | Maximum file size to scan in MB |
| `--exts` | *(all text files)* | Comma-separated extensions to scan exclusively |
| `--skip-exts` | *(none)* | Comma-separated extensions to skip |
| `--skip-folders` | *(none)* | Comma-separated folder names to skip at startup |
| `--no-screenshot` | `false` | Disable base64 screenshot capture |

---

## PHI/SPII Redaction (`--redact-sensitive`)

When scanning environments that may contain patient records or government-issued
identifiers, use `--redact-sensitive` to prevent actual sensitive values from
being written to the output CSV or appearing in the terminal.

```bash
# Recommended for any scan where the CSV will be shared, exported, or stored
./scanner --redact-sensitive /mnt/fileserver/hr
./scanner --local --redact-sensitive ~/Documents
```

### What is suppressed

| Field | Normal mode | `--redact-sensitive` |
|---|---|---|
| `LinePreview` | First matching line (truncated) | **Empty** |
| `Screenshot_Base64` | Base64-encoded context block | **Empty** |
| Console preview lines | Shown under each finding | Replaced with `[redacted — PHI/SPII]` |

### What is still logged

All other finding fields are written to CSV unchanged:

`ScanDate`, `SharePath`, `Folder`, `FileName`, `FileExtension`, `PatternName`,
`Severity`, `LineNumbers`, `Permissions`, `Owner`, `FileSizeBytes`

This means you still know **where** the data lives and **what type** it is —
just not the actual value.

### Patterns covered

The following patterns are classified as PHI or SPII and are suppressed when
`--redact-sensitive` is active:

| Pattern | Category |
|---|---|
| `SSN` | SPII — US Social Security Number |
| `Credit Card` | SPII — Payment card number |
| `Passport Number` | SPII — Government-issued travel document |
| `National ID` | SPII — National/government ID number |
| `Date of Birth` | SPII — Date of birth label with value |
| `NHS Number` | PHI — UK National Health Service identifier |
| `ICD Code` | PHI — Medical diagnosis code |
| `HIPAA Keywords` | PHI — Patient ID, MRN, diagnosis, prescription, medication |

All other patterns (credentials, API keys, AWS keys, connection strings, etc.)
are unaffected — their previews and screenshots are always captured.

### Adding patterns to the sensitive list

Edit `internal/patterns/patterns.go` and add the pattern name to the
`sensitivePatterns` map:

```go
var sensitivePatterns = map[string]struct{}{
    "SSN":             {},
    "My New PHI Pattern": {}, // ← add here
    // ...
}
```

---

## Interactive Commands

Type these commands in the terminal while a scan is running:

```
p  / pause        — Pause the scan (workers finish their current file then block)
r  / resume       — Resume a paused scan
s  / status       — Show live counters: walked, scanned, skipped, findings, current file
sf <name>         — Skip all folders whose name matches <name>  (e.g. sf archive)
se <ext>          — Skip all files with extension <ext>         (e.g. se .log)
q  / quit         — Stop the scan and exit
h  / help         — Show the command list
```

Skip commands take effect immediately for the next file picked up by a worker.
Already-running files complete normally.

---

## File Permissions

The `Permissions` column captures the effective permissions of the scanning
account against each file.

**Linux / macOS example:**
```
RW- owner:jsmith mode:-rw-r--r--
```

**Windows example:**
```
RW- owner:CORP\jsmith mode:-rw-rw-rw- attrs:READONLY|ARCHIVE
```

The `attrs` field on Windows reflects Win32 `GetFileAttributes` flags:

| Flag | Meaning |
|---|---|
| `READONLY` | File is marked read-only |
| `HIDDEN` | File is hidden from normal directory listings |
| `SYSTEM` | File is a Windows system file |
| `ARCHIVE` | File has been modified since last backup |
| `COMPRESSED` | File is NTFS-compressed |
| `ENCRYPTED` | File is EFS-encrypted |
| `OFFLINE` | File data is not immediately available (e.g. HSM tiered storage) |
| `SPARSE` | File is a sparse file |
| `SYMLINK/JUNCTION` | Reparse point (symbolic link or directory junction) |

---

## Windows Owner Lookup — How It Works

On Windows, owner resolution uses the Windows Security API via
`golang.org/x/sys/windows`. This is a fully implemented lookup — not a stub —
using four sequential API calls:

```
CreateFile(READ_CONTROL)          ← open a handle with minimal privilege
  → GetSecurityInfo()             ← retrieve the security descriptor (owner SID only)
    → sd.Owner()                  ← extract the SID from the descriptor
      → sid.LookupAccount("")     ← resolve SID → DOMAIN\Username
```

If `LookupAccount` fails (e.g. an orphaned SID from a deleted domain account),
the raw SID string is returned instead (e.g. `S-1-5-21-3623811015-...`) rather
than erroring out.

### Where golang.org/x/sys/windows lives

| Location | Purpose |
|---|---|
| `go.mod` | Declares `require golang.org/x/sys v0.15.0` |
| `go.sum` | Cryptographic hashes for integrity verification at build time |
| `vendor/golang.org/x/sys/windows/` | Full package source, vendored locally — no internet needed to build |
| `vendor/modules.txt` | Go's vendor index — maps packages to their declared versions |
| `internal/permissions/owner_windows.go` | The **only** file that `import`s it, tagged `//go:build windows` |

Because `owner_windows.go` carries `//go:build windows`, the compiler completely
ignores this file — and the entire `golang.org/x/sys/windows` package — when
building on Linux or macOS.

---

## Pattern Categories

| Category | Patterns Included |
|---|---|
| **Credentials** | Plain-text passwords, API keys, generic tokens and secrets |
| **AWS / Cloud** | AWS access keys, AWS secret keys, Docker/Kubernetes secrets |
| **Certificates & Keys** | PEM private key blocks, PEM certificate blocks, SSH host keys |
| **PII** | SSN, credit card numbers (Visa/MC/Amex/Discover), email addresses, phone numbers, dates of birth, passport numbers, national IDs |
| **Financial** | IBAN, BIC/SWIFT codes, Bitcoin wallet addresses |
| **Healthcare** | NHS numbers, ICD-10 codes, HIPAA-sensitive keywords (patient ID, MRN, diagnosis, prescription) |
| **Infrastructure** | RFC-1918 private IPs in configs, internal hostnames (`.local`/`.internal`), database connection strings, JDBC URLs |

---

## Project Structure

```
filescanner/
├── cmd/
│   └── scanner/
│       └── main.go                  ← Entry point, CLI flags, path resolution, interactive console
├── internal/
│   ├── scanner/
│   │   └── scanner.go               ← Core walk + concurrent scan engine (LocalMode-aware)
│   ├── patterns/
│   │   └── patterns.go              ← All 27 regex patterns (add new ones here)
│   ├── control/
│   │   └── control.go               ← Pause/resume/skip channel-based controller
│   ├── permissions/
│   │   ├── permissions.go           ← Platform-agnostic: Get(), FilePerms struct
│   │   ├── owner_unix.go            ← //go:build !windows  UID → username via syscall
│   │   ├── owner_windows.go         ← //go:build windows   GetSecurityInfo → LookupAccountSid
│   │   ├── attr_stub.go             ← //go:build !windows  no-op windowsAttributes()
│   │   └── attr_windows.go          ← //go:build windows   GetFileAttributes bridge
│   ├── screenshot/
│   │   └── screenshot.go            ← Redacted context capture → base64
│   └── output/
│       └── csv.go                   ← Thread-safe CSV writer + summary report
├── pkg/
│   └── plugin/
│       ├── plugin.go                ← Plugin interface + Registry
│       └── examples/
│           └── hashplugin/
│               └── hash.go          ← Example plugin: SHA-256 hash logger
├── vendor/
│   ├── modules.txt                  ← Go vendor index
│   └── golang.org/x/sys/windows/   ← Vendored Windows API package (v0.15.0)
├── csv_to_excel.py                  ← Excel exporter with embedded screenshots
├── go.mod                           ← Module definition + dependency declaration
├── go.sum                           ← Dependency integrity hashes
└── README.md
```

### Key files changed in this version

| File | Change |
|---|---|
| `cmd/scanner/main.go` | Added `--local` flag; `resolvePaths()` for `~` expansion, relative path resolution, and directory validation; `isLikelyLocalPath()` heuristic for share-mode warnings; `--redact-sensitive` flag wired to `cfg.RedactSensitive`; banner shows `Redact PHI` line; updated usage text |
| `internal/scanner/scanner.go` | Added `LocalMode bool` and `RedactSensitive bool` to `Config`; walk loop and finding output use context-sensitive labels; console preview lines and CSV `LinePreview`/`Screenshot` fields are suppressed per-finding when pattern is PHI/SPII and `RedactSensitive` is active |
| `internal/patterns/patterns.go` | Added `sensitivePatterns` map and `IsSensitivePattern(name string) bool` helper used by the scanner engine to identify PHI/SPII patterns at runtime |

---

## Adding Patterns

Edit `internal/patterns/patterns.go` and add an entry to the `defs` slice
inside `DefaultPatterns()`:

```go
{
    name:     "My Custom Pattern",
    desc:     "Detects widget serial numbers",
    regex:    `(?i)widget[_-]?serial\s*[:=]\s*[A-Z0-9]{12}`,
    severity: "HIGH",
},
```

Severity must be one of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`. The pattern is
compiled once at startup and applied to every line of every text file scanned.

---

## Writing a Plugin

Implement the `plugin.Plugin` interface. Embed `plugin.NoopPlugin` so you only
need to override the hooks you care about:

```go
package alertplugin

import (
    "fmt"
    "filescanner/internal/output"
    "filescanner/pkg/plugin"
)

type AlertPlugin struct{ plugin.NoopPlugin }

func (p *AlertPlugin) Name() string { return "slack-alerter" }

func (p *AlertPlugin) OnFinding(ctx *plugin.Context, f *output.Finding) {
    if f.Severity == "CRITICAL" {
        fmt.Printf("[ALERT] CRITICAL: %s in %s (lines %v)\n",
            f.PatternName, f.FileName, f.LineNumbers)
    }
}

func (p *AlertPlugin) OnScanComplete(totalFiles, findings int) {
    fmt.Printf("[alert-plugin] Scan done: %d findings in %d files\n", findings, totalFiles)
}
```

Register it in `cmd/scanner/main.go`:

```go
plugins.Register(&alertplugin.AlertPlugin{})
```

### Plugin hooks

| Hook | When called | Useful for |
|---|---|---|
| `OnFileStart(ctx)` | Before each file is scanned | Pre-processing, allow-listing |
| `OnFinding(ctx, finding)` | For each pattern match | Alerting, deduplication, SIEM forwarding |
| `OnFileEnd(ctx)` | After a file is fully processed | Per-file summaries, cleanup |
| `OnScanComplete(files, findings)` | Once when the scan finishes | Final reports, metric submission |

The `plugin.Context` passed to each hook contains the file path, `os.FileInfo`,
all file lines (for text files), and the findings accumulated so far for that file.

---

## Building

### Linux / macOS
```bash
go build -o scanner ./cmd/scanner/
```

### Windows (native)
```cmd
go build -o scanner.exe .\cmd\scanner\
```

### Windows (cross-compile from Linux / macOS)
```bash
GOOS=windows GOARCH=amd64 go build -o scanner.exe ./cmd/scanner/
```

No CGO, no external toolchain required. The `vendor/` directory means no
internet access is needed at build time — everything is self-contained.

---

## Requirements

| Component | Requirement |
|---|---|
| Go scanner | Go 1.22+ |
| Excel exporter | Python 3.10+, `openpyxl`, `pillow` |
| Windows owner lookup | Run as an account with `READ_CONTROL` access to the files being scanned |
| Linux/macOS owner lookup | No elevated privileges required beyond read access to the files |
