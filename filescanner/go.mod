module filescanner

// go 1.20 is declared intentionally.
//
// Windows compatibility matrix (determined by the BUILD TOOLCHAIN, not this file):
//
//   Go 1.20.x  →  runs on Windows 7 SP1 / Server 2008 R2 and later  (version 6.1+)
//   Go 1.21+   →  runs on Windows 10 (build 10586) / Server 2016 ONLY
//
// WHY: Go 1.21 changed the runtime to call ProcessPrng() from bcryptprimitives.dll
// at program startup. That function does not exist on Windows 7/8/8.1/Server 2008-2012.
// The binary exits immediately with "not compatible with this version of Windows".
// This has nothing to do with our code — it is a Go runtime change.
//
// If you need to target older Windows, install Go 1.20.14 and build with:
//   Windows:  .\build_windows.ps1 -OldWindows
//   Linux:    ./build.sh --old-windows
//
// If Windows 10+ is acceptable, any Go 1.20+ toolchain works fine.
go 1.20

// golang.org/x/sys/windows is imported ONLY by internal/permissions/owner_windows.go
// which carries a //go:build windows tag.  On Linux/macOS this dependency is
// never compiled or linked — it is present purely for Windows builds.
require golang.org/x/sys v0.15.0
