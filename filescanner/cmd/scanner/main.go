package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filescanner/internal/control"
	"filescanner/internal/output"
	"filescanner/internal/scanner"
	"filescanner/pkg/plugin"
)

func main() {
	outputCSV := flag.String("out", "scan_results.csv", "Output CSV file path")
	workers := flag.Int("workers", 4, "Number of concurrent scan workers")
	maxSizeMB := flag.Int64("maxsize", 50, "Maximum file size to scan (MB)")
	noScreenshot := flag.Bool("no-screenshot", false, "Disable text screenshot capture")
	exts := flag.String("exts", "", "Comma-separated extensions to scan (empty=all text)")
	skipExtsFlag := flag.String("skip-exts", "", "Comma-separated extensions to skip")
	skipFoldersFlag := flag.String("skip-folders", "", "Comma-separated folder names/paths to skip")
	flag.Usage = printUsage
	flag.Parse()

	shares := flag.Args()
	if len(shares) == 0 {
		fmt.Fprintln(os.Stderr, "Error: at least one share path is required.")
		printUsage()
		os.Exit(1)
	}

	timestamp := time.Now().Format("20060102_150405")
	outPath := *outputCSV
	if outPath == "scan_results.csv" {
		outPath = fmt.Sprintf("scan_%s.csv", timestamp)
	}
	if !filepath.IsAbs(outPath) {
		cwd, _ := os.Getwd()
		outPath = filepath.Join(cwd, outPath)
	}

	cfg := scanner.DefaultConfig()
	cfg.Shares = shares
	cfg.OutputCSV = outPath
	cfg.WorkerCount = *workers
	cfg.MaxFileSize = *maxSizeMB * 1024 * 1024
	cfg.TakeScreenshot = !*noScreenshot

	if *exts != "" {
		for _, e := range strings.Split(*exts, ",") {
			if e = strings.TrimSpace(e); e != "" {
				cfg.ScanExtensions = append(cfg.ScanExtensions, e)
			}
		}
	}

	ctrl := control.New()
	if *skipExtsFlag != "" {
		for _, e := range strings.Split(*skipExtsFlag, ",") {
			ctrl.AddSkipExt(strings.TrimSpace(e))
		}
	}
	if *skipFoldersFlag != "" {
		for _, f := range strings.Split(*skipFoldersFlag, ",") {
			ctrl.AddSkipFolder(strings.TrimSpace(f))
		}
	}

	plugins := &plugin.Registry{}
	plugins.Register(&summaryPlugin{})

	s, err := scanner.New(cfg, ctrl, plugins)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create scanner: %v\n", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[!] Interrupt received — stopping scan...")
		ctrl.Stop()
	}()

	go runConsole(ctrl, s)
	printBanner(cfg, outPath)

	if err := s.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		os.Exit(1)
	}
}

func runConsole(ctrl *control.Controller, s *scanner.Scanner) {
	sc := bufio.NewScanner(os.Stdin)
	printHelp()
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToLower(parts[0])
		switch cmd {
		case "p", "pause":
			ctrl.Pause()
			fmt.Println("[>] Scan PAUSED. Type 'r' to resume.")
		case "r", "resume":
			ctrl.Resume()
			fmt.Println("[>] Scan RESUMED.")
		case "q", "quit", "exit":
			fmt.Println("[>] Stopping scan...")
			ctrl.Stop()
			return
		case "sf":
			folder := ""
			if len(parts) >= 2 {
				folder = strings.TrimSpace(parts[1])
			}
			if folder == "" {
				fmt.Print("[>] Enter folder name/path to skip: ")
				if sc.Scan() {
					folder = strings.TrimSpace(sc.Text())
				}
			}
			if folder != "" {
				ctrl.AddSkipFolder(folder)
				fmt.Printf("[>] Will skip folders matching: %q\n", folder)
			}
		case "se":
			ext := ""
			if len(parts) >= 2 {
				ext = strings.TrimSpace(parts[1])
			}
			if ext == "" {
				fmt.Print("[>] Enter file extension to skip (e.g. .log): ")
				if sc.Scan() {
					ext = strings.TrimSpace(sc.Text())
				}
			}
			if ext != "" {
				ctrl.AddSkipExt(ext)
				fmt.Printf("[>] Will skip extension: %q\n", ext)
			}
		case "status", "s":
			st := s.Stats()
			cur, _ := st.CurrentFile.Load().(string)
			fmt.Printf("[>] State: %-8s | Walked: %d | Scanned: %d | Skipped: %d | Findings: %d\n",
				ctrl.State(), st.FilesWalked.Load(), st.FilesScanned.Load(),
				st.FilesSkipped.Load(), st.FindingsTotal.Load())
			fmt.Printf("[>] Current: %s\n", cur)
			fmt.Printf("[>] Skipped folders: %v\n", ctrl.SkippedFolders())
			fmt.Printf("[>] Skipped exts   : %v\n", ctrl.SkippedExts())
		case "help", "h", "?":
			printHelp()
		default:
			fmt.Printf("[>] Unknown command %q — type 'help'\n", cmd)
		}
	}
}

func printHelp() {
	fmt.Print(`
┌──────────────────────────────────────────────────────┐
│             Interactive Console Commands              │
├──────────────┬───────────────────────────────────────┤
│  p / pause   │ Pause the scan                        │
│  r / resume  │ Resume a paused scan                  │
│  s / status  │ Show live progress stats              │
│  sf <name>   │ Skip folders matching <name>          │
│  se <ext>    │ Skip files with extension <ext>       │
│  q / quit    │ Stop and exit                         │
│  h / help    │ Show this help                        │
└──────────────┴───────────────────────────────────────┘
`)
}

func printBanner(cfg scanner.Config, outPath string) {
	fmt.Print(`
╔══════════════════════════════════════════════════════════╗
║          FILE SHARE SENSITIVE DATA SCANNER               ║
╚══════════════════════════════════════════════════════════╝
`)
	fmt.Printf("  Shares    : %s\n", strings.Join(cfg.Shares, ", "))
	fmt.Printf("  Output    : %s\n", outPath)
	fmt.Printf("  Workers   : %d\n", cfg.WorkerCount)
	fmt.Printf("  Max size  : %d MB\n", cfg.MaxFileSize/1024/1024)
	fmt.Printf("  Patterns  : %d loaded\n", len(cfg.Patterns))
	fmt.Printf("  Screenshot: %v\n\n", cfg.TakeScreenshot)
	fmt.Println("  Scan running — type 'help' for interactive commands")
	fmt.Println()
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `
FileScanner — Sensitive Data Scanner for File Shares

Usage:
  scanner [flags] <share_path> [share_path2 ...]

Flags:
`)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Examples:
  scanner /mnt/fileserver/shared
  scanner --out results.csv --workers 8 /data/hr /data/finance
  scanner --skip-exts .log,.tmp --skip-folders archive /shares/ops
  scanner --exts .env,.config,.yml /etc
`)
}

type summaryPlugin struct{ plugin.NoopPlugin }

func (sp *summaryPlugin) Name() string { return "summary-logger" }
func (sp *summaryPlugin) OnFinding(_ *plugin.Context, f *output.Finding) { _ = f }
func (sp *summaryPlugin) OnScanComplete(totalFiles, findings int) {
	if findings == 0 {
		fmt.Println("\n[✓] No sensitive data patterns detected.")
	} else {
		fmt.Printf("\n[!] %d sensitive finding(s) across %d file(s) scanned.\n", findings, totalFiles)
	}
}
