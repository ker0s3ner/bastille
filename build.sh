#!/bin/bash
# THL Modern — top-level build script
# Requires: live-build, debootstrap, squashfs-tools, xorriso
# Run as root inside the build/ directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

echo "=== Tinfoil Hat Linux Modern — Build ==="
echo "Build dir: $BUILD_DIR"
echo

# Sanity checks
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: live-build must run as root (or under sudo)." >&2
  exit 1
fi

command -v lb >/dev/null 2>&1 || {
  echo "ERROR: live-build not found. Install with: apt install live-build" >&2
  exit 1
}

# Make auto/* scripts executable
chmod +x "$BUILD_DIR"/auto/*
chmod +x "$BUILD_DIR"/config/hooks/live/*.hook.chroot 2>/dev/null || true

cd "$BUILD_DIR"

echo "--- Configuring live-build ---"
lb config

echo "--- Building ISO ---"
lb build

ISO=$(ls -1t "$BUILD_DIR"/live-image-amd64.hybrid.iso 2>/dev/null | head -1)
if [ -n "$ISO" ]; then
  echo
  echo "=== Build complete ==="
  echo "ISO: $ISO"
  sha512sum "$ISO"
else
  echo "ERROR: ISO not found after build — check build.log" >&2
  exit 1
fi
