#!/usr/bin/env bash
# Build the scanner container image with tuned configs from security-scanner.
#
# Usage:
#   ./build-scanner.sh                    # Build on OCP
#   ./build-scanner.sh --local            # Build locally with podman/docker
#   SCANNER_REPO=/path/to/scanner ./build-scanner.sh  # Custom scanner repo path
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCANNER_REPO="${SCANNER_REPO:-$(dirname "$SCRIPT_DIR")/../security-scanner}"
BUILD_DIR=$(mktemp -d)

echo "Assembling build context..."
cp -R "$SCRIPT_DIR"/* "$BUILD_DIR/"
cp "$SCANNER_REPO/scripts/scan-repo.sh" "$BUILD_DIR/scan-repo.sh"
cp -R "$SCANNER_REPO/configs" "$BUILD_DIR/configs"
echo "  scan-repo.sh: $(wc -l < "$BUILD_DIR/scan-repo.sh") lines"
echo "  configs: $(ls "$BUILD_DIR/configs/" | wc -l | tr -d ' ') files"

if [ "${1:-}" = "--local" ]; then
  RUNTIME="${RUNTIME:-podman}"
  echo "Building locally with ${RUNTIME}..."
  ${RUNTIME} build -f "$BUILD_DIR/Dockerfile.scanner" \
    --platform linux/amd64 \
    -t quay.io/ugiordan/security-audit-scanner:latest \
    "$BUILD_DIR"
else
  echo "Building on OCP..."
  oc start-build security-audit-scanner \
    --from-dir="$BUILD_DIR" \
    -n rhoai-security \
    --follow
fi

rm -rf "$BUILD_DIR"
echo "Done."
