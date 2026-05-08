// Package scanner is the core engine that walks file shares and detects sensitive data.
package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"filescanner/internal/control"
	"filescanner/internal/output"
	"filescanner/internal/patterns"
	"filescanner/internal/permissions"
	"filescanner/internal/screenshot"
	"filescanner/pkg/plugin"
)

const (
	defaultMaxFileSize = 50 * 1024 * 1024
	defaultWorkerCount = 4
)

// Config holds scanner configuration.
type Config struct {
	Shares         []string
	OutputCSV      string
	MaxFileSize    int64
	WorkerCount    int
	TakeScreenshot bool
	Patterns       []patterns.Pattern
	// ScanExtensions: if non-empty, only files with these extensions are scanned.
	ScanExtensions []string
	// LocalMode indicates the targets are local filesystem directories rather
	// than network shares.  Affects console labels only; the walk logic is
	// identical for both modes.
	LocalMode bool
	// RedactSensitive suppresses LinePreview, console previews, and Screenshot
	// for any finding whose pattern is classified as PHI or SPII (SSN, credit
	// card, passport, national ID, NHS number, ICD code, HIPAA keywords, date
	// of birth).  All other finding fields (file path, pattern name, severity,
	// line numbers, permissions, owner) are still written to CSV normally.
	RedactSensitive bool
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		MaxFileSize:    defaultMaxFileSize,
		WorkerCount:    defaultWorkerCount,
		TakeScreenshot: true,
		Patterns:       patterns.DefaultPatterns(),
	}
}

// Stats tracks live progress counters.
type Stats struct {
	FilesWalked   atomic.Int64
	FilesScanned  atomic.Int64
	FilesSkipped  atomic.Int64
	FindingsTotal atomic.Int64
	CurrentFile   atomic.Value // stores string
}

// Scanner is the main orchestrator.
type Scanner struct {
	cfg       Config
	ctrl      *control.Controller
	csv       *output.CSVWriter
	plugins   *plugin.Registry
	stats     Stats
	startTime time.Time
}

// New creates a Scanner. Call Run() to start.
func New(cfg Config, ctrl *control.Controller, plugins *plugin.Registry) (*Scanner, error) {
	if len(cfg.Shares) == 0 {
		return nil, fmt.Errorf("no shares specified")
	}
	if plugins == nil {
		plugins = &plugin.Registry{}
	}
	return &Scanner{
		cfg:     cfg,
		ctrl:    ctrl,
		plugins: plugins,
	}, nil
}

// Run starts the scan and blocks until complete or stopped.
func (s *Scanner) Run() error {
	s.startTime = time.Now()

	cw, err := output.NewCSVWriter(s.cfg.OutputCSV)
	if err != nil {
		return fmt.Errorf("open output: %w", err)
	}
	defer cw.Close()
	s.csv = cw

	workCh := make(chan string, s.cfg.WorkerCount*4)
	var wg sync.WaitGroup

	for i := 0; i < s.cfg.WorkerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range workCh {
				if s.ctrl.IsStopped() {
					return
				}
				s.scanFile(path)
			}
		}()
	}

	// Walk all shares/local folders — multiple targets are fully supported.
	targetLabel := "share"
	if s.cfg.LocalMode {
		targetLabel = "folder"
	}
	for _, share := range s.cfg.Shares {
		if s.ctrl.IsStopped() {
			break
		}
		fmt.Printf("\n  [>] Walking %s: %s\n", targetLabel, share)
		if err := s.walk(share, workCh); err != nil {
			if err.Error() != "stopped" {
				fmt.Printf("  [!] Walk error on %s: %v\n", share, err)
			}
		}
	}

	close(workCh)
	wg.Wait()

	s.plugins.FireOnScanComplete(int(s.stats.FilesScanned.Load()), int(s.stats.FindingsTotal.Load()))

	output.SummaryReport(
		cw.Path(),
		int(s.stats.FilesScanned.Load()),
		int(s.stats.FilesSkipped.Load()),
		int(s.stats.FindingsTotal.Load()),
		time.Since(s.startTime),
	)
	return nil
}

// Stats returns a pointer to the live stats structure.
func (s *Scanner) Stats() *Stats { return &s.stats }

// walk recursively enqueues files from root into workCh.
//
// Key fixes vs original:
//  1. The root path itself is NEVER tested against the skip-folder list.
//     Only subdirectories encountered during descent are checked.
//     Previously, if the root share path contained a word that was in the
//     skip list (e.g. scanning \\server\archive when "archive" was a skip
//     term), filepath.Walk would call the callback with the root as a dir
//     first, ShouldSkipFolder would match, and SkipDir would be returned —
//     silently scanning nothing at all.
//  2. ShouldSkipFolder now matches only against filepath.Base(path) (the
//     final directory name component), not the entire path string.  This
//     prevents a skip term of "logs" from accidentally skipping
//     "\\fileserver\logs\2024\hr" when only the subfolder "logs" under some
//     share was intended to be skipped.
func (s *Scanner) walk(root string, workCh chan<- string) error {
	root = filepath.Clean(root)

	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("  [!] Access error: %s — %v\n", path, err)
			return nil // log and continue walking the rest of the tree
		}

		if s.ctrl.IsStopped() {
			return fmt.Errorf("stopped")
		}
		if !s.ctrl.WaitIfPaused() {
			return fmt.Errorf("stopped")
		}

		if info.IsDir() {
			// Never apply skip logic to the root itself — only to subdirs.
			if path != root && s.ctrl.ShouldSkipFolder(filepath.Base(path)) {
				fmt.Printf("  [~] Skipping folder : %s\n", path)
				s.stats.FilesSkipped.Add(1)
				return filepath.SkipDir
			}
			return nil
		}

		s.stats.FilesWalked.Add(1)

		ext := strings.ToLower(filepath.Ext(path))
		if s.ctrl.ShouldSkipExt(ext) {
			s.stats.FilesSkipped.Add(1)
			return nil
		}
		if len(s.cfg.ScanExtensions) > 0 && !containsExt(s.cfg.ScanExtensions, ext) {
			s.stats.FilesSkipped.Add(1)
			return nil
		}

		if info.Size() > s.cfg.MaxFileSize {
			fmt.Printf("  [~] Skipping large file (%d MB): %s\n", info.Size()/1024/1024, path)
			s.stats.FilesSkipped.Add(1)
			return nil
		}

		workCh <- path
		return nil
	})
}

// severityColour returns an ANSI colour prefix for the severity level.
// Falls back to plain text on terminals that don't support colour.
func severityColour(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return "\033[1;31m" // bold red
	case "HIGH":
		return "\033[0;31m" // red
	case "MEDIUM":
		return "\033[0;33m" // yellow
	case "LOW":
		return "\033[0;32m" // green
	default:
		return "\033[0m"
	}
}

const colourReset = "\033[0m"

// scanFile scans one file for sensitive patterns and prints enriched findings.
func (s *Scanner) scanFile(path string) {
	if !s.ctrl.WaitIfPaused() {
		return
	}

	s.stats.CurrentFile.Store(path)

	info, err := os.Stat(path)
	if err != nil {
		return
	}

	if !isTextFile(path) {
		s.stats.FilesSkipped.Add(1)
		return
	}

	s.stats.FilesScanned.Add(1)

	lines, err := readLines(path)
	if err != nil {
		return
	}

	perms, _ := permissions.Get(path)

	ctx := &plugin.Context{
		FilePath: path,
		Info:     info,
		Lines:    lines,
	}
	s.plugins.FireOnFileStart(ctx)

	type patternHit struct {
		lineNums []int
		previews []string // one preview per matched line (capped)
		severity string
	}
	hits := make(map[string]*patternHit)

	for lineIdx, line := range lines {
		lineNum := lineIdx + 1
		for _, pat := range s.cfg.Patterns {
			if pat.Regex.MatchString(line) {
				h, ok := hits[pat.Name]
				if !ok {
					h = &patternHit{severity: pat.Severity}
					hits[pat.Name] = h
				}
				h.lineNums = append(h.lineNums, lineNum)
				// Keep up to 3 line previews per pattern.
				if len(h.previews) < 3 {
					h.previews = append(h.previews, truncateLine(strings.TrimSpace(line), 100))
				}
			}
		}
	}

	if len(hits) == 0 {
		s.plugins.FireOnFileEnd(ctx)
		return
	}

	// Collect all matched line numbers for screenshot.
	var allMatchedLines []int
	for _, h := range hits {
		allMatchedLines = append(allMatchedLines, h.lineNums...)
	}
	sort.Ints(allMatchedLines)

	var screenshotData string
	if s.cfg.TakeScreenshot {
		screenshotData = screenshot.Capture(path, lines, allMatchedLines)
	}

	folder := filepath.Dir(path)
	fileName := filepath.Base(path)
	ext := filepath.Ext(fileName)
	sharePath := shareRoot(path, s.cfg.Shares)

	// ── Console output ────────────────────────────────────────────────────
	// Print a clearly formatted block per file so operators can read the
	// terminal output without needing to open the CSV.
	//
	// Example:
	//   ┌─ FINDING ────────────────────────────────────────────────────────┐
	//   │  File       : /data/hr/employees/config.yml
	//   │  Share      : /data/hr
	//   │  Permissions: RW- owner:jsmith mode:-rw-r--r--
	//   │
	//   │  [CRITICAL] Password in Config          lines: 4, 17
	//   │             └─ password: "Sup3rS3cret!"
	//   │             └─ passwd = hunter2
	//   │
	//   │  [HIGH]     AWS Access Key               lines: 22
	//   │             └─ aws_access_key=AKIAIOSFODNN7EXAMPLE
	//   └──────────────────────────────────────────────────────────────────┘

	sourceLabel := "Share"
	if s.cfg.LocalMode {
		sourceLabel = "Folder"
	}

	fmt.Println()
	fmt.Println("  ┌─ FINDING " + strings.Repeat("─", 58) + "┐")
	fmt.Printf("  │  File       : %s\n", path)
	fmt.Printf("  │  %-11s: %s\n", sourceLabel, sharePath)
	fmt.Printf("  │  Permissions: %s\n", perms.String())
	fmt.Println("  │")

	// Sort hits by severity for consistent display order.
	type namedHit struct {
		name string
		hit  *patternHit
	}
	sevOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
	var sorted []namedHit
	for name, h := range hits {
		sorted = append(sorted, namedHit{name, h})
	}
	sort.Slice(sorted, func(i, j int) bool {
		oi := sevOrder[strings.ToUpper(sorted[i].hit.severity)]
		oj := sevOrder[strings.ToUpper(sorted[j].hit.severity)]
		if oi != oj {
			return oi < oj
		}
		return sorted[i].name < sorted[j].name
	})

	for _, nh := range sorted {
		h := nh.hit
		col := severityColour(h.severity)
		tag := fmt.Sprintf("[%s]", strings.ToUpper(h.severity))
		lineList := formatLineNums(h.lineNums)

		fmt.Printf("  │  %s%-10s%s %-35s lines: %s\n",
			col, tag, colourReset, nh.name, lineList)

		if s.cfg.RedactSensitive && patterns.IsSensitivePattern(nh.name) {
			fmt.Printf("  │             └─ %s[redacted — PHI/SPII]%s\n", col, colourReset)
		} else {
			for _, preview := range h.previews {
				fmt.Printf("  │             └─ %s\n", preview)
			}
		}
		fmt.Println("  │")
	}

	fmt.Println("  └" + strings.Repeat("─", 67) + "┘")

	// ── CSV write ─────────────────────────────────────────────────────────
	for _, nh := range sorted {
		h := nh.hit

		// Determine whether this pattern contains PHI/SPII that must be
		// suppressed.  When RedactSensitive is active the LinePreview and
		// Screenshot fields are blanked; everything else is logged normally.
		isSensitive := s.cfg.RedactSensitive && patterns.IsSensitivePattern(nh.name)

		preview := ""
		if !isSensitive && len(h.previews) > 0 {
			preview = h.previews[0]
		}

		shot := screenshotData
		if isSensitive {
			shot = ""
		}

		finding := output.Finding{
			ScanDate:      time.Now(),
			SharePath:     sharePath,
			Folder:        folder,
			FileName:      fileName,
			FileExtension: ext,
			PatternName:   nh.name,
			Severity:      h.severity,
			LineNumbers:   h.lineNums,
			LinePreview:   preview,
			Permissions:   perms.String(),
			Owner:         perms.Owner,
			FileSize:      info.Size(),
			Screenshot:    shot,
		}

		ctx.Findings = append(ctx.Findings, finding)
		s.plugins.FireOnFinding(ctx, &finding)

		if err := s.csv.Write(finding); err != nil {
			fmt.Printf("  [!] CSV write error: %v\n", err)
		}
		s.stats.FindingsTotal.Add(1)
	}

	s.plugins.FireOnFileEnd(ctx)
}

// formatLineNums formats a slice of line numbers compactly.
// Up to 8 are shown individually; beyond that a count is appended.
//   [1, 3, 7]         → "1, 3, 7"
//   [1..12 total 12]  → "1, 2, 3, 4, 5, 6, 7, 8 (+4 more)"
func formatLineNums(nums []int) string {
	if len(nums) == 0 {
		return ""
	}
	const maxShow = 8
	parts := make([]string, 0, maxShow)
	for i, n := range nums {
		if i >= maxShow {
			parts = append(parts, fmt.Sprintf("(+%d more)", len(nums)-maxShow))
			break
		}
		parts = append(parts, fmt.Sprintf("%d", n))
	}
	return strings.Join(parts, ", ")
}

// shareRoot returns the share root that contains path.
// It ensures both sides have a trailing separator before comparing so that
// a share of "/data/hr" does not accidentally match a path of "/data/hr2/...".
func shareRoot(path string, shares []string) string {
	cleanPath := filepath.Clean(path)
	for _, share := range shares {
		cleanShare := filepath.Clean(share)
		// Add separator to avoid prefix false-matches between sibling dirs.
		if strings.HasPrefix(cleanPath+string(filepath.Separator), cleanShare+string(filepath.Separator)) {
			return share
		}
	}
	return filepath.VolumeName(path)
}

// readLines reads all lines from a file into a string slice.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

// isTextFile returns true if the file has a known text extension or its
// first 512 bytes contain no non-printable control characters.
func isTextFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	textExts := map[string]struct{}{
		".txt": {}, ".log": {}, ".csv": {}, ".json": {}, ".xml": {},
		".yaml": {}, ".yml": {}, ".toml": {}, ".ini": {}, ".conf": {},
		".cfg": {}, ".env": {}, ".sh": {}, ".bat": {}, ".ps1": {},
		".py": {}, ".js": {}, ".ts": {}, ".go": {}, ".java": {},
		".cs": {}, ".php": {}, ".rb": {}, ".c": {}, ".cpp": {},
		".h": {}, ".sql": {}, ".md": {}, ".html": {}, ".htm": {},
		".properties": {}, ".pem": {}, ".crt": {}, ".key": {},
		".config": {}, ".tf": {}, ".hcl": {}, ".gradle": {},
		".dockerfile": {}, ".jenkinsfile": {}, ".gitignore": {},
		".bashrc": {}, ".profile": {}, ".zshrc": {},
	}
	if _, ok := textExts[ext]; ok {
		return true
	}

	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil || n == 0 {
		return false
	}
	for _, b := range buf[:n] {
		r := rune(b)
		if b < 0x09 || (b > 0x0d && b < 0x20 && b != 0x1b) {
			if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
				return false
			}
		}
	}
	return true
}

func truncateLine(s string, max int) string {
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

func shortenPath(path string, max int) string {
	if len(path) <= max {
		return path
	}
	return "…" + path[len(path)-max+1:]
}

func containsExt(exts []string, ext string) bool {
	for _, e := range exts {
		if strings.EqualFold(e, ext) {
			return true
		}
	}
	return false
}
