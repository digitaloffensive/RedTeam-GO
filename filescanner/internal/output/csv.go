// Package output handles CSV result writing.
package output

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Finding represents one flagged item written to the CSV.
type Finding struct {
	ScanDate      time.Time
	SharePath     string
	Folder        string
	FileName      string
	FileExtension string
	PatternName   string
	Severity      string
	LineNumbers   []int
	LinePreview   string
	Permissions   string
	Owner         string
	FileSize      int64
	Screenshot    string // base64-encoded text block
}

// CSVWriter writes findings to a CSV file in a thread-safe manner.
type CSVWriter struct {
	mu      sync.Mutex
	file    *os.File
	writer  *csv.Writer
	path    string
	count   int
}

var csvHeaders = []string{
	"ScanDate",
	"SharePath",
	"Folder",
	"FileName",
	"FileExtension",
	"PatternName",
	"Severity",
	"LineNumbers",
	"LinePreview",
	"Permissions",
	"Owner",
	"FileSizeBytes",
	"Screenshot_Base64",
}

// NewCSVWriter opens (or creates) the output CSV at path and writes the header.
func NewCSVWriter(path string) (*CSVWriter, error) {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	needsHeader := !fileExists(path)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open CSV file: %w", err)
	}

	w := csv.NewWriter(f)
	cw := &CSVWriter{file: f, writer: w, path: path}

	if needsHeader {
		if err := w.Write(csvHeaders); err != nil {
			f.Close()
			return nil, fmt.Errorf("write CSV header: %w", err)
		}
		w.Flush()
	}

	return cw, nil
}

// Write adds a Finding to the CSV. Safe for concurrent use.
func (cw *CSVWriter) Write(f Finding) error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	lineNums := make([]string, len(f.LineNumbers))
	for i, n := range f.LineNumbers {
		lineNums[i] = fmt.Sprintf("%d", n)
	}

	row := []string{
		f.ScanDate.Format("2006-01-02 15:04:05"),
		f.SharePath,
		f.Folder,
		f.FileName,
		f.FileExtension,
		f.PatternName,
		f.Severity,
		strings.Join(lineNums, ","),
		f.LinePreview,
		f.Permissions,
		f.Owner,
		fmt.Sprintf("%d", f.FileSize),
		f.Screenshot,
	}

	if err := cw.writer.Write(row); err != nil {
		return err
	}
	cw.writer.Flush()
	cw.count++
	return cw.writer.Error()
}

// Count returns the number of findings written.
func (cw *CSVWriter) Count() int {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	return cw.count
}

// Path returns the output file path.
func (cw *CSVWriter) Path() string { return cw.path }

// Close flushes and closes the underlying file.
func (cw *CSVWriter) Close() error {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	cw.writer.Flush()
	return cw.file.Close()
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// SummaryReport prints a brief summary to stdout.
func SummaryReport(csvPath string, totalFiles, skipped, findingCount int, elapsed time.Duration) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║              SCAN COMPLETE — SUMMARY                 ║")
	fmt.Println("╠══════════════════════════════════════════════════════╣")
	fmt.Printf("║  Files scanned   : %-32d ║\n", totalFiles)
	fmt.Printf("║  Files skipped   : %-32d ║\n", skipped)
	fmt.Printf("║  Findings logged : %-32d ║\n", findingCount)
	fmt.Printf("║  Elapsed time    : %-32s ║\n", elapsed.Round(time.Second).String())
	fmt.Printf("║  Output CSV      : %-32s ║\n", truncate(csvPath, 32))
	fmt.Println("╚══════════════════════════════════════════════════════╝")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return "…" + s[len(s)-max+1:]
}
