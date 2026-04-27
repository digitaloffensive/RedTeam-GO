//go:build windows

package permissions

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// fixLongPath prepends the \\?\ extended-length path prefix when a path
// exceeds MAX_PATH (260 chars). This is required for GetFileAttributes,
// CreateFile, and other Win32 APIs on deep directory trees common on
// file servers.
//
//   Regular path : C:\very\long\path\...
//   Extended     : \\?\C:\very\long\path\...
//   UNC path     : \\server\share\path\...
//   Extended UNC : \\?\UNC\server\share\path\...
func fixLongPath(path string) string {
	if len(path) < windows.MAX_PATH {
		return path
	}
	// Already extended.
	if strings.HasPrefix(path, `\\?\`) {
		return path
	}
	// UNC path: \\server\share → \\?\UNC\server\share
	if strings.HasPrefix(path, `\\`) {
		return `\\?\UNC\` + path[2:]
	}
	// Regular absolute path
	return `\\?\` + path
}

// getOwner satisfies the cross-platform signature in permissions.go.
// On Windows, os.FileInfo.Sys() returns *syscall.Win32FileAttributeData
// which does NOT contain the file path, so the real lookup is deferred to
// getWindowsOwner() where the path string is available.
// permissions.Get() calls windowsAttributes(path) which returns the owner
// alongside the attribute flags, so this function just returns "" as a signal
// to use that result instead.
func getOwner(_ os.FileInfo) string { return "" }

// getWindowsOwner resolves the owner of path using the Windows Security API.
//
// Steps:
//  1. CreateFile        — open a handle with READ_CONTROL (minimal privilege)
//  2. GetSecurityInfo   — fetch the SECURITY_DESCRIPTOR (OWNER_SECURITY_INFORMATION only)
//  3. sd.Owner()        — extract the owner SID from the descriptor
//  4. sid.LookupAccount — resolve SID → "DOMAIN\Username"
//
// Graceful fallbacks:
//   - If CreateFile fails (access denied, file in use) → "err:open(<reason>)"
//   - If GetSecurityInfo fails                         → "err:getsec(<reason>)"
//   - If LookupAccount fails (orphaned/deleted SID)    → raw SID string e.g. S-1-5-21-…
func getWindowsOwner(path string) string {
	epath := fixLongPath(path)
	pathPtr, err := windows.UTF16PtrFromString(epath)
	if err != nil {
		return fmt.Sprintf("err:utf16(%v)", err)
	}

	// Open with READ_CONTROL only — sufficient to read the owner SID,
	// does not require SeSecurityPrivilege or elevated rights.
	handle, err := windows.CreateFile(
		pathPtr,
		windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS, // required to open directories
		0,
	)
	if err != nil {
		return fmt.Sprintf("err:open(%v)", err)
	}
	defer windows.CloseHandle(handle)

	// Request OWNER_SECURITY_INFORMATION only — avoids needing SeSecurityPrivilege
	// that SACL_SECURITY_INFORMATION would require.
	sd, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Sprintf("err:getsec(%v)", err)
	}

	ownerSID, _, err := sd.Owner()
	if err != nil || ownerSID == nil {
		return "unknown-sid"
	}

	// LookupAccount against the local machine (empty system name = local).
	account, domain, _, err := ownerSID.LookupAccount("")
	if err != nil {
		// Orphaned SID — user/group deleted from the domain.
		// Return the raw SID rather than erroring.
		return ownerSID.String()
	}

	if domain != "" {
		return domain + `\` + account
	}
	return account
}

// canWriteWindows checks whether the current process can write to path by
// attempting to open it with GENERIC_WRITE access.
//
// Why not use os.OpenFile(O_WRONLY|O_APPEND)?
//   On Windows, O_WRONLY maps to GENERIC_WRITE which works on local files,
//   but on network shares the sharing mode and oplock negotiation can cause
//   ERROR_SHARING_VIOLATION even for files that ARE writable, producing false
//   negatives. Using FILE_SHARE_READ|WRITE|DELETE with OPEN_EXISTING and
//   GENERIC_WRITE gives accurate results for both local and UNC paths.
func canWriteWindows(path string) bool {
	epath := fixLongPath(path)
	pathPtr, err := windows.UTF16PtrFromString(epath)
	if err != nil {
		return false
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return false
	}
	windows.CloseHandle(handle)
	return true
}

// canReadWindows checks whether the current process can read path by
// attempting to open it with GENERIC_READ access and full share flags.
func canReadWindows(path string) bool {
	epath := fixLongPath(path)
	pathPtr, err := windows.UTF16PtrFromString(epath)
	if err != nil {
		return false
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return false
	}
	windows.CloseHandle(handle)
	return true
}

// windowsFileAttributes returns (attrFlagString, owner) for path by calling
// GetFileAttributes and getWindowsOwner.
//
// All FILE_ATTRIBUTE_* constants used here come from golang.org/x/sys/windows
// (types_windows.go and zerrors_windows.go) — no magic numbers.
func windowsFileAttributes(path string) (attrs string, owner string) {
	owner = getWindowsOwner(path)

	epath := fixLongPath(path)
	pathPtr, err := windows.UTF16PtrFromString(epath)
	if err != nil {
		return "", owner
	}

	rawAttrs, err := windows.GetFileAttributes(pathPtr)
	if err != nil {
		return "", owner
	}

	// All constants are from golang.org/x/sys/windows (no hardcoded hex).
	// FILE_ATTRIBUTE_TEMPORARY and FILE_ATTRIBUTE_ENCRYPTED live in
	// zerrors_windows.go but are still exported as windows.FILE_ATTRIBUTE_*.
	flags := []struct {
		bit  uint32
		name string
	}{
		{windows.FILE_ATTRIBUTE_READONLY, "READONLY"},
		{windows.FILE_ATTRIBUTE_HIDDEN, "HIDDEN"},
		{windows.FILE_ATTRIBUTE_SYSTEM, "SYSTEM"},
		{windows.FILE_ATTRIBUTE_ARCHIVE, "ARCHIVE"},
		{windows.FILE_ATTRIBUTE_TEMPORARY, "TEMP"},
		{windows.FILE_ATTRIBUTE_SPARSE_FILE, "SPARSE"},
		{windows.FILE_ATTRIBUTE_REPARSE_POINT, "SYMLINK/JUNCTION"},
		{windows.FILE_ATTRIBUTE_COMPRESSED, "COMPRESSED"},
		{windows.FILE_ATTRIBUTE_OFFLINE, "OFFLINE"},
		{windows.FILE_ATTRIBUTE_ENCRYPTED, "ENCRYPTED"},
	}

	var parts []string
	for _, f := range flags {
		if rawAttrs&f.bit != 0 {
			parts = append(parts, f.name)
		}
	}

	return strings.Join(parts, "|"), owner
}
