// Package hashplugin is an example plugin that logs SHA-256 hashes of flagged files.
// Drop this into your build and register it with plugins.Register(hashplugin.New()).
package hashplugin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"filescanner/internal/output"
	"filescanner/pkg/plugin"
)

// Plugin logs the SHA-256 hash of every file that has findings.
type Plugin struct {
	plugin.NoopPlugin
	hashed map[string]struct{}
}

// New creates a new hash-logging plugin.
func New() *Plugin {
	return &Plugin{hashed: make(map[string]struct{})}
}

func (p *Plugin) Name() string { return "sha256-hasher" }

func (p *Plugin) OnFinding(ctx *plugin.Context, f *output.Finding) {
	if _, done := p.hashed[ctx.FilePath]; done {
		return
	}
	p.hashed[ctx.FilePath] = struct{}{}

	hash, err := sha256File(ctx.FilePath)
	if err != nil {
		return
	}
	fmt.Printf("[hash-plugin] %s  %s\n", hash, ctx.FilePath)
}

func (p *Plugin) OnScanComplete(totalFiles, findings int) {
	fmt.Printf("[hash-plugin] Hashed %d flagged files.\n", len(p.hashed))
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
