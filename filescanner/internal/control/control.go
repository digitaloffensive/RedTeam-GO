// Package control provides pause/resume/skip signalling for the scanner.
package control

import (
	"strings"
	"sync"
)

// State constants.
const (
	StateRunning = "running"
	StatePaused  = "paused"
	StateStopped = "stopped"
)

// Controller manages the run-state and skip lists.
type Controller struct {
	mu           sync.RWMutex
	state        string
	pauseCh      chan struct{} // closed when resumed
	skipFolders  map[string]struct{}
	skipExts     map[string]struct{}
	skipRequests []SkipRequest
}

// SkipRequest is a pending skip submitted from the UI goroutine.
type SkipRequest struct {
	Type  string // "folder" | "ext"
	Value string
}

// New creates a Controller in the running state.
func New() *Controller {
	c := &Controller{
		state:       StateRunning,
		pauseCh:     make(chan struct{}),
		skipFolders: make(map[string]struct{}),
		skipExts:    make(map[string]struct{}),
	}
	// Start un-paused: close the channel so WaitIfPaused returns immediately.
	close(c.pauseCh)
	return c
}

// Pause puts the scanner into paused state.
func (c *Controller) Pause() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == StateRunning {
		c.state = StatePaused
		c.pauseCh = make(chan struct{}) // new un-closed channel
	}
}

// Resume unblocks a paused scanner.
func (c *Controller) Resume() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == StatePaused {
		c.state = StateRunning
		close(c.pauseCh) // unblock all WaitIfPaused callers
	}
}

// Stop signals a permanent halt.
func (c *Controller) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != StateStopped {
		c.state = StateStopped
		// Ensure pause channel is closed so any blocked goroutine wakes.
		select {
		case <-c.pauseCh:
		default:
			close(c.pauseCh)
		}
	}
}

// State returns the current state string.
func (c *Controller) State() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// WaitIfPaused blocks until the scanner is resumed or stopped.
// Returns false if the controller has been stopped.
func (c *Controller) WaitIfPaused() bool {
	for {
		c.mu.RLock()
		ch := c.pauseCh
		state := c.state
		c.mu.RUnlock()

		if state == StateStopped {
			return false
		}
		// Block on pause channel; when closed we loop again to check state.
		<-ch
		c.mu.RLock()
		newState := c.state
		c.mu.RUnlock()
		if newState == StateRunning {
			return true
		}
		if newState == StateStopped {
			return false
		}
	}
}

// IsStopped returns true if Stop() has been called.
func (c *Controller) IsStopped() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state == StateStopped
}

// AddSkipFolder registers a folder name or path prefix to skip.
func (c *Controller) AddSkipFolder(folder string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.skipFolders[strings.ToLower(folder)] = struct{}{}
}

// AddSkipExt registers a file extension to skip (with or without dot).
func (c *Controller) AddSkipExt(ext string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	c.skipExts[strings.ToLower(ext)] = struct{}{}
}

// ShouldSkipFolder reports whether a folder path/name should be skipped.
func (c *Controller) ShouldSkipFolder(path string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	lower := strings.ToLower(path)
	for k := range c.skipFolders {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}

// ShouldSkipExt reports whether a file extension should be skipped.
func (c *Controller) ShouldSkipExt(ext string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	_, ok := c.skipExts[strings.ToLower(ext)]
	return ok
}

// SkippedFolders returns a copy of the current skip-folder set.
func (c *Controller) SkippedFolders() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, 0, len(c.skipFolders))
	for k := range c.skipFolders {
		out = append(out, k)
	}
	return out
}

// SkippedExts returns a copy of the current skip-ext set.
func (c *Controller) SkippedExts() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, 0, len(c.skipExts))
	for k := range c.skipExts {
		out = append(out, k)
	}
	return out
}
