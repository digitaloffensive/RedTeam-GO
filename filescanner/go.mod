module filescanner

go 1.22.2

// golang.org/x/sys/windows is imported ONLY by internal/permissions/owner_windows.go
// which carries a //go:build windows tag.  On Linux/macOS this dependency is
// never compiled or linked — it is present purely for Windows builds.
require golang.org/x/sys v0.15.0
