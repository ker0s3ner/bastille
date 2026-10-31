#!/bin/bash
# Local AMD64 ISO build using Dockerfile.build.amd64
# Output: build/live-image-amd64.hybrid.iso
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/build"
mkdir -p "$OUTPUT_DIR"

echo "=== Bastille AMD64 — Local Docker Build ==="

echo "--- Building builder image (linux/amd64) ---"
docker build \
  --platform linux/amd64 \
  -f "$SCRIPT_DIR/Dockerfile.build.amd64" \
  -t bastille-amd64-builder \
  "$SCRIPT_DIR"

echo "--- Running ISO build inside container ---"
docker run --rm --privileged \
  --platform linux/amd64 \
  -v "$OUTPUT_DIR:/output" \
  bastille-amd64-builder \
  bash -c '
    set -euo pipefail
    bash /bastille/build.sh --architectures amd64
    ISO=$(ls -1t /bastille/build/live-image-*.hybrid.iso 2>/dev/null | head -1)
    cp "$ISO" /output/live-image-amd64.hybrid.iso
    echo "Copied to /output/live-image-amd64.hybrid.iso"
  '

echo ""
echo "=== Done ==="
ls -lh "$OUTPUT_DIR/live-image-amd64.hybrid.iso"
sha256sum "$OUTPUT_DIR/live-image-amd64.hybrid.iso"
