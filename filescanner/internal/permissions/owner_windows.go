//go:build windows

package permissions

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// getOwner satisfies the cross-platform signature used by permissions.go.
// On Windows, os.FileInfo.Sys() returns *syscall.Win32FileAttributeData which
// does NOT contain the file path, so we cannot look up the owner from FileInfo
// alone.  Instead, the real lookup is done by windowsOwnerFromPath (called via
// windowsAttributes) which has access to the path string.
//
// This function returns a sentinel that signals callers to use the path-based
// lookup instead.  permissions.Get() handles this transparently.
func getOwner(_ os.FileInfo) string {
	// Actual lookup happens in windowsFileAttributes / getWindowsOwner where
	// the path string is available.  Return empty so Get() uses the enriched path.
	return ""
}

// getWindowsOwner resolves the file owner for path using the Windows Security API:
//
//  1. CreateFile        — open a handle with READ_CONTROL access
//  2. GetSecurityInfo   — retrieve the SECURITY_DESCRIPTOR (owner SID only)
//  3. Owner()           — extract the owner SID from the descriptor
//  4. LookupAccount     — resolve SID → DOMAIN\Username
func getWindowsOwner(path string) string {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "err:utf16"
	}

	// Open with READ_CONTROL only — minimal privilege required for owner lookup.
	handle, err := windows.CreateFile(
		pathPtr,
		windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS, // must be set to open directories too
		0,
	)
	if err != nil {
		return fmt.Sprintf("err:open(%v)", err)
	}
	defer windows.CloseHandle(handle)

	// Request only OWNER_SECURITY_INFORMATION to minimise privilege requirements.
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

	// LookupAccount resolves the SID on the local machine (empty system name).
	account, domain, _, err := ownerSID.LookupAccount("")
	if err != nil {
		// Fall back to the raw SID string (e.g. S-1-5-21-…) rather than failing.
		return ownerSID.String()
	}

	if domain != "" {
		return domain + `\` + account
	}
	return account
}

// windowsFileAttributes reads Win32 file attribute flags and the owner for path.
// Called by attr_windows.go → permissions.Get() on Windows builds.
func windowsFileAttributes(path string) (attrs string, owner string) {
	owner = getWindowsOwner(path)

	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", owner
	}

	rawAttrs, err := windows.GetFileAttributes(pathPtr)
	if err != nil {
		return "", owner
	}

	flags := []struct {
		bit  uint32
		name string
	}{
		{windows.FILE_ATTRIBUTE_READONLY, "READONLY"},
		{windows.FILE_ATTRIBUTE_HIDDEN, "HIDDEN"},
		{windows.FILE_ATTRIBUTE_SYSTEM, "SYSTEM"},
		{windows.FILE_ATTRIBUTE_ARCHIVE, "ARCHIVE"},
		{0x00000100, "TEMP"},       // FILE_ATTRIBUTE_TEMPORARY
		{windows.FILE_ATTRIBUTE_COMPRESSED, "COMPRESSED"},
		{windows.FILE_ATTRIBUTE_ENCRYPTED, "ENCRYPTED"},
		{windows.FILE_ATTRIBUTE_OFFLINE, "OFFLINE"},
		{windows.FILE_ATTRIBUTE_SPARSE_FILE, "SPARSE"},
		{windows.FILE_ATTRIBUTE_REPARSE_POINT, "SYMLINK/JUNCTION"},
		{0x00004000, "ENCRYPTED"},  // FILE_ATTRIBUTE_ENCRYPTED duplicate guard handled below
	}

	seen := map[string]struct{}{}
	result := ""
	for _, f := range flags {
		if rawAttrs&f.bit != 0 {
			if _, dup := seen[f.name]; dup {
				continue
			}
			seen[f.name] = struct{}{}
			if result != "" {
				result += "|"
			}
			result += f.name
		}
	}

	return result, owner
}
