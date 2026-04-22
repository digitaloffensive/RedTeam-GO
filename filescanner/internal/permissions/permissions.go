// Package permissions detects file permission attributes in a cross-platform way.
package permissions

import (
	"fmt"
	"os"
	"runtime"
)

// FilePerms holds human-readable permission information.
type FilePerms struct {
	Readable  bool
	Writable  bool
	Executable bool
	Owner     string
	ModeStr   string
	RawMode   os.FileMode
}

// String returns a compact representation, e.g. "R W X owner:SYSTEM mode:0644"
func (fp FilePerms) String() string {
	r := boolStr(fp.Readable, "R", "-")
	w := boolStr(fp.Writable, "W", "-")
	x := boolStr(fp.Executable, "X", "-")
	return fmt.Sprintf("%s%s%s owner:%s mode:%s", r, w, x, fp.Owner, fp.ModeStr)
}

func boolStr(v bool, t, f string) string {
	if v { return t }
	return f
}

// Get returns the permissions for the given path.
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

	// Readable / Writable / Executable via file open attempts
	fp.Readable = canRead(path)
	fp.Writable = canWrite(path)
	fp.Executable = (mode&0111 != 0)

	fp.Owner = getOwner(info)

	_ = runtime.GOOS // suppress unused import warning on non-Unix
	return fp, nil
}

func canRead(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func canWrite(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}
