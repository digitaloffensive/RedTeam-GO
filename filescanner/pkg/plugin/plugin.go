// Package plugin defines the extension interface for the file scanner.
// To add a new capability (e.g. hash logging, YARA rules, cloud upload),
// implement the Plugin interface and register it with scanner.RegisterPlugin().
package plugin

import (
	"filescanner/internal/output"
	"os"
)

// Context is passed to each plugin hook during a scan.
type Context struct {
	// FilePath is the full path to the file being scanned.
	FilePath string
	// Info is the os.FileInfo for the file.
	Info os.FileInfo
	// Lines is the file content split into lines (nil for binary files).
	Lines []string
	// Findings accumulated so far for this file (read-only, do not modify).
	Findings []output.Finding
}

// Plugin is the extension interface.
// All methods are optional — embed NoopPlugin to implement only what you need.
type Plugin interface {
	// Name returns the plugin's identifier.
	Name() string
	// OnFileStart is called before a file is scanned.
	OnFileStart(ctx *Context)
	// OnFinding is called for each sensitive finding detected.
	OnFinding(ctx *Context, finding *output.Finding)
	// OnFileEnd is called after a file has been fully scanned.
	OnFileEnd(ctx *Context)
	// OnScanComplete is called once when the entire scan finishes.
	OnScanComplete(totalFiles, findings int)
}

// NoopPlugin provides empty implementations of all Plugin methods.
// Embed this in your plugin and override only what you need.
type NoopPlugin struct{}

func (NoopPlugin) Name() string                                      { return "noop" }
func (NoopPlugin) OnFileStart(ctx *Context)                          {}
func (NoopPlugin) OnFinding(ctx *Context, finding *output.Finding)   {}
func (NoopPlugin) OnFileEnd(ctx *Context)                            {}
func (NoopPlugin) OnScanComplete(totalFiles, findings int)           {}

// Registry holds all registered plugins.
type Registry struct {
	plugins []Plugin
}

// Register adds a plugin to the registry.
func (r *Registry) Register(p Plugin) {
	r.plugins = append(r.plugins, p)
}

// All returns all registered plugins.
func (r *Registry) All() []Plugin {
	return r.plugins
}

// FireOnFileStart calls OnFileStart on all plugins.
func (r *Registry) FireOnFileStart(ctx *Context) {
	for _, p := range r.plugins {
		p.OnFileStart(ctx)
	}
}

// FireOnFinding calls OnFinding on all plugins.
func (r *Registry) FireOnFinding(ctx *Context, f *output.Finding) {
	for _, p := range r.plugins {
		p.OnFinding(ctx, f)
	}
}

// FireOnFileEnd calls OnFileEnd on all plugins.
func (r *Registry) FireOnFileEnd(ctx *Context) {
	for _, p := range r.plugins {
		p.OnFileEnd(ctx)
	}
}

// FireOnScanComplete calls OnScanComplete on all plugins.
func (r *Registry) FireOnScanComplete(totalFiles, findings int) {
	for _, p := range r.plugins {
		p.OnScanComplete(totalFiles, findings)
	}
}
