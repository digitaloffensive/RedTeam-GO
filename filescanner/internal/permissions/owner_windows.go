//go:build windows

package permissions

import "os"

func getOwner(info os.FileInfo) string {
	// On Windows, ownership lookup requires Windows API calls.
	// A full implementation would use golang.org/x/sys/windows.
	// This stub returns a placeholder; extend as needed.
	return "windows-owner-lookup-not-implemented"
}
