#!/bin/bash
# Local ARM64 ISO build using Dockerfile.build
# Output: build/live-image-arm64.hybrid.iso
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/build"
mkdir -p "$OUTPUT_DIR"

echo "=== Bastille ARM64 — Local Docker Build ==="

echo "--- Building builder image (linux/arm64) ---"
docker build \
  --platform linux/arm64 \
  -f "$SCRIPT_DIR/Dockerfile.build" \
  -t bastille-arm64-builder \
  "$SCRIPT_DIR"

echo "--- Running ISO build inside container ---"
docker run --rm --privileged \
  --platform linux/arm64 \
  -v "$OUTPUT_DIR:/output" \
  bastille-arm64-builder \
  bash -c '
    set -euo pipefail
    bash /bastille/build.sh
    ISO=$(ls -1t /bastille/build/live-image-*.hybrid.iso 2>/dev/null | head -1)
    cp "$ISO" /output/live-image-arm64.hybrid.iso
    echo "Copied to /output/live-image-arm64.hybrid.iso"
  '

echo ""
echo "=== Done ==="
ls -lh "$OUTPUT_DIR/live-image-arm64.hybrid.iso"
sha256sum "$OUTPUT_DIR/live-image-arm64.hybrid.iso"
