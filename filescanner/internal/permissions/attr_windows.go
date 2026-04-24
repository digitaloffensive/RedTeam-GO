//go:build windows

package permissions

// windowsAttributes returns (attrFlags, owner) for the given path.
// Delegates to windowsFileAttributes() in owner_windows.go which calls
// GetFileAttributes and GetSecurityInfo via golang.org/x/sys/windows.
func windowsAttributes(path string) (string, string) {
	return windowsFileAttributes(path)
}
