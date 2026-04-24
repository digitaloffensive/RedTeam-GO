//go:build !windows

package permissions

// windowsAttributes is a no-op on Linux and macOS — returns empty strings for
// both the attribute flags and owner (owner is resolved by owner_unix.go instead).
func windowsAttributes(_ string) (string, string) {
	return "", ""
}
