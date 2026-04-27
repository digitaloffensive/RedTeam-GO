//go:build !windows

package permissions

import "os"

// canRead on Linux/macOS uses os.Open — a direct read attempt.
func canRead(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// canWrite on Linux/macOS uses os.OpenFile with O_WRONLY|O_APPEND.
// This does not truncate or modify the file. On Linux the kernel correctly
// returns EACCES when write permission is denied, so this is accurate.
func canWrite(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}
