// Package permissions detects file permission attributes in a cross-platform way.
//
// Platform behaviour:
//   - Linux / macOS: owner resolved via syscall.Stat_t UID → user.LookupId
//   - Windows:       owner resolved via GetSecurityInfo + LookupAccountSid
//                    (requires golang.org/x/sys/windows, only compiled on Windows)
package permissions

import (
	"fmt"
	"os"
)

// FilePerms holds human-readable permission information.
type FilePerms struct {
	Readable       bool
	Writable       bool
	Executable     bool
	Owner          string
	ModeStr        string
	RawMode        os.FileMode
	// WindowsAttrs contains Windows-specific attribute flags
	// (e.g. HIDDEN|READONLY|ENCRYPTED).  Empty on non-Windows.
	WindowsAttrs   string
}

// String returns a compact single-line representation suitable for CSV logging.
// Linux/Mac example:  RW- owner:jsmith mode:-rw-r--r--
// Windows example:    RW- owner:CORP\jsmith mode:-rw-rw-rw- attrs:READONLY|ARCHIVE
func (fp FilePerms) String() string {
	r := boolStr(fp.Readable, "R", "-")
	w := boolStr(fp.Writable, "W", "-")
	x := boolStr(fp.Executable, "X", "-")
	s := fmt.Sprintf("%s%s%s owner:%s mode:%s", r, w, x, fp.Owner, fp.ModeStr)
	if fp.WindowsAttrs != "" {
		s += " attrs:" + fp.WindowsAttrs
	}
	return s
}

func boolStr(v bool, t, f string) string {
	if v {
		return t
	}
	return f
}

// Get returns the permissions for the given path.
// It works on Linux, macOS, and Windows without any build-tag changes in
// calling code — the platform-specific parts are in owner_unix.go and
// owner_windows.go respectively.
func Get(path string) (FilePerms, error) {
	info, err := os.Stat(path)
	if err != nil {
		return FilePerms{}, err
	}
	mode := info.Mode()

	fp := FilePerms{
		RawMode: mode,
		ModeStr: mode.String(),
	}

	fp.Readable   = canRead(path)
	fp.Writable   = canWrite(path)
	fp.Executable = mode&0111 != 0

	// On Windows: windowsAttributes returns (attrFlags, owner) via the Windows
	// Security API (GetFileAttributes + GetSecurityInfo → LookupAccount).
	// On Linux/macOS: returns ("", "") and we fall through to getOwner() which
	// uses syscall.Stat_t UID → user.LookupId.
	winAttrs, winOwner := windowsAttributes(path)
	fp.WindowsAttrs = winAttrs

	if winOwner != "" {
		// Windows path: owner came from GetSecurityInfo → LookupAccountSid.
		fp.Owner = winOwner
	} else {
		// Unix path: owner from syscall UID lookup (owner_unix.go).
		fp.Owner = getOwner(info)
	}

	return fp, nil
}

// canRead and canWrite are implemented per-platform:
//   canaccess_unix.go    — uses os.Open / os.OpenFile (Linux, macOS)
//   canaccess_windows.go — uses CreateFile with GENERIC_READ/WRITE and full
//                          share flags, correctly handling UNC paths and
//                          network share locking behaviour on Windows
