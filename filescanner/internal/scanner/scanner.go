// Package scanner is the core engine that walks file shares and detects sensitive data.
package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
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
	// maxFileSize is the largest file we'll attempt to scan (default 50 MB).
	defaultMaxFileSize = 50 * 1024 * 1024
	// workerCount is the number of concurrent file-scanning goroutines.
	defaultWorkerCount = 4
)

// Config holds scanner configuration.
type Config struct {
	Shares          []string
	OutputCSV       string
	MaxFileSize     int64
	WorkerCount     int
	TakeScreenshot  bool
	Patterns        []patterns.Pattern
	// ScanExtensions: if non-empty, only files with these extensions are scanned.
	ScanExtensions []string
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
	FilesWalked  atomic.Int64
	FilesScanned atomic.Int64
	FilesSkipped atomic.Int64
	FindingsTotal atomic.Int64
	CurrentFile  atomic.Value // stores string
}

// Scanner is the main orchestrator.
type Scanner struct {
	cfg      Config
	ctrl     *control.Controller
	csv      *output.CSVWriter
	plugins  *plugin.Registry
	stats    Stats
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

	// Open CSV writer.
	cw, err := output.NewCSVWriter(s.cfg.OutputCSV)
	if err != nil {
		return fmt.Errorf("open output: %w", err)
	}
	defer cw.Close()
	s.csv = cw

	// File work queue.
	workCh := make(chan string, s.cfg.WorkerCount*4)
	var wg sync.WaitGroup

	// Start workers.
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

	// Walk all shares.
	for _, share := range s.cfg.Shares {
		if s.ctrl.IsStopped() {
			break
		}
		fmt.Printf("[scanner] Walking share: %s\n", share)
		if err := s.walk(share, workCh); err != nil {
			fmt.Printf("[scanner] Walk error on %s: %v\n", share, err)
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

// walk recursively enqueues files from root.
func (s *Scanner) walk(root string, workCh chan<- string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("[scanner] Access error: %s: %v\n", path, err)
			return nil // continue walking
		}

		// Check stop/pause on every entry.
		if s.ctrl.IsStopped() {
			return fmt.Errorf("stopped")
		}
		if !s.ctrl.WaitIfPaused() {
			return fmt.Errorf("stopped")
		}

		if info.IsDir() {
			if s.ctrl.ShouldSkipFolder(path) {
				fmt.Printf("[scanner] Skipping folder: %s\n", path)
				s.stats.FilesSkipped.Add(1)
				return filepath.SkipDir
			}
			return nil
		}

		s.stats.FilesWalked.Add(1)

		// Extension filter.
		ext := strings.ToLower(filepath.Ext(path))
		if s.ctrl.ShouldSkipExt(ext) {
			s.stats.FilesSkipped.Add(1)
			return nil
		}
		if len(s.cfg.ScanExtensions) > 0 && !containsExt(s.cfg.ScanExtensions, ext) {
			s.stats.FilesSkipped.Add(1)
			return nil
		}

		// Size filter.
		if info.Size() > s.cfg.MaxFileSize {
			fmt.Printf("[scanner] Skipping large file (%d MB): %s\n", info.Size()/1024/1024, path)
			s.stats.FilesSkipped.Add(1)
			return nil
		}

		workCh <- path
		return nil
	})
}

// scanFile scans one file for sensitive patterns.
func (s *Scanner) scanFile(path string) {
	if !s.ctrl.WaitIfPaused() {
		return
	}

	s.stats.CurrentFile.Store(path)

	info, err := os.Stat(path)
	if err != nil {
		return
	}

	// Skip non-text files.
	if !isTextFile(path) {
		s.stats.FilesSkipped.Add(1)
		return
	}

	s.stats.FilesScanned.Add(1)

	// Read file lines.
	lines, err := readLines(path)
	if err != nil {
		return
	}

	// Get permissions.
	perms, _ := permissions.Get(path)

	// Plugin: OnFileStart
	ctx := &plugin.Context{
		FilePath: path,
		Info:     info,
		Lines:    lines,
	}
	s.plugins.FireOnFileStart(ctx)

	// Detect patterns.
	// Map: patternName -> list of line numbers
	type patternHit struct {
		lineNums []int
		preview  string
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
				if h.preview == "" {
					h.preview = truncateLine(line, 120)
				}
			}
		}
	}

	if len(hits) == 0 {
		s.plugins.FireOnFileEnd(ctx)
		return
	}

	// Collect all matched line numbers for screenshot.
	allMatchedLines := []int{}
	for _, h := range hits {
		allMatchedLines = append(allMatchedLines, h.lineNums...)
	}

	var screenshotData string
	if s.cfg.TakeScreenshot {
		screenshotData = screenshot.Capture(path, lines, allMatchedLines)
	}

	folder := filepath.Dir(path)
	fileName := filepath.Base(path)
	ext := filepath.Ext(fileName)
	sharePath := shareRoot(path, s.cfg.Shares)

	for patName, h := range hits {
		finding := output.Finding{
			ScanDate:      time.Now(),
			SharePath:     sharePath,
			Folder:        folder,
			FileName:      fileName,
			FileExtension: ext,
			PatternName:   patName,
			Severity:      h.severity,
			LineNumbers:   h.lineNums,
			LinePreview:   h.preview,
			Permissions:   perms.String(),
			Owner:         perms.Owner,
			FileSize:      info.Size(),
			Screenshot:    screenshotData,
		}

		ctx.Findings = append(ctx.Findings, finding)
		s.plugins.FireOnFinding(ctx, &finding)

		if err := s.csv.Write(finding); err != nil {
			fmt.Printf("[scanner] CSV write error: %v\n", err)
		}
		s.stats.FindingsTotal.Add(1)

		fmt.Printf("[+] FOUND %-12s  %-45s  lines:%v\n",
			"["+h.severity+"]",
			shortenPath(path, 45),
			h.lineNums,
		)
	}

	s.plugins.FireOnFileEnd(ctx)
}

// shareRoot returns the share root that contains path.
func shareRoot(path string, shares []string) string {
	for _, s := range shares {
		if strings.HasPrefix(path, s) {
			return s
		}
	}
	return filepath.VolumeName(path)
}

// readLines reads all lines from a file.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024) // 1 MB line buffer
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

// isTextFile does a quick binary sniff on the first 512 bytes.
func isTextFile(path string) bool {
	// Allow common text-based extensions regardless of content sniff.
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
