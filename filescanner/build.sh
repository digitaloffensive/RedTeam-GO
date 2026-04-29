#!/usr/bin/env bash
# build.sh — Build FileScanner for all platforms
# Detects Go version and warns about Windows compatibility.
#
# Usage:
#   ./build.sh                  # build all targets
#   ./build.sh --old-windows    # enforce Go 1.20 for Win7/8 support
#   ./build.sh --target amd64   # build one target only
set -euo pipefail

TARGETS=("linux/amd64" "windows/amd64" "windows/arm64")
OLD_WINDOWS=false
SPECIFIC_TARGET=""

for arg in "$@"; do
    case $arg in
        --old-windows) OLD_WINDOWS=true ;;
        --target) shift; SPECIFIC_TARGET="$1" ;;
    esac
done

# ── Go version check ──────────────────────────────────────────────────────────
GO_VERSION=$(go version 2>/dev/null | grep -oP 'go\K[0-9]+\.[0-9]+' | head -1)
GO_MAJOR=$(echo "$GO_VERSION" | cut -d. -f1)
GO_MINOR=$(echo "$GO_VERSION" | cut -d. -f2)

echo "Detected Go: go${GO_MAJOR}.${GO_MINOR}"

IS_MODERN=false
if [ "$GO_MAJOR" -gt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -ge 21 ]; }; then
    IS_MODERN=true
fi

if $OLD_WINDOWS; then
    if $IS_MODERN; then
        echo ""
        echo "ERROR: --old-windows requires Go 1.20.x but you have go${GO_MAJOR}.${GO_MINOR}"
        echo ""
        echo "Go 1.21+ binaries WILL NOT RUN on:"
        echo "  Windows 7 / Server 2008 R2   (version 6.1)"
        echo "  Windows 8 / Server 2012      (version 6.2)"
        echo "  Windows 8.1 / Server 2012 R2 (version 6.3)"
        echo ""
        echo "They crash with: 'not compatible with this version of Windows'"
        echo "Root cause: Go 1.21+ calls ProcessPrng() from bcryptprimitives.dll"
        echo "at startup. This function does not exist on pre-Windows 10 systems."
        echo ""
        echo "Fix: install Go 1.20.14 from https://go.dev/dl/#go1.20.14"
        echo "     then re-run: ./build.sh --old-windows"
        exit 1
    fi
    echo "Building with Go ${GO_MAJOR}.${GO_MINOR} — Windows 7 SP1+ compatible"
elif $IS_MODERN; then
    echo "NOTE: Go ${GO_MAJOR}.${GO_MINOR} — output requires Windows 10 / Server 2016+"
    echo "      For older Windows use: ./build.sh --old-windows"
fi

echo ""

# ── Build ─────────────────────────────────────────────────────────────────────
SUFFIX=$(if $IS_MODERN; then echo "win10plus"; else echo "win7plus"; fi)
mkdir -p dist

build_target() {
    local GOOS GOARCH
    GOOS=$(echo "$1" | cut -d/ -f1)
    GOARCH=$(echo "$1" | cut -d/ -f2)

    local NAME
    if [ "$GOOS" = "windows" ]; then
        NAME="dist/scanner_${GOOS}_${GOARCH}_${SUFFIX}.exe"
    else
        NAME="dist/scanner_${GOOS}_${GOARCH}"
    fi

    printf "  Building %-45s ... " "$NAME"
    GOOS=$GOOS GOARCH=$GOARCH go build \
        -trimpath \
        -ldflags="-s -w" \
        -o "$NAME" \
        ./cmd/scanner/
    local SIZE
    SIZE=$(du -sh "$NAME" | cut -f1)
    echo "OK ($SIZE)"
}

if [ -n "$SPECIFIC_TARGET" ]; then
    build_target "$SPECIFIC_TARGET"
else
    for T in "${TARGETS[@]}"; do
        build_target "$T"
    done
fi

echo ""
echo "Build complete. Output in ./dist/"
if $IS_MODERN; then
    echo "Windows minimum: Windows 10 build 10586 (version 1511) / Server 2016+"
else
    echo "Windows minimum: Windows 7 SP1 / Server 2008 R2+"
fi
