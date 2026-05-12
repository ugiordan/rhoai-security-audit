#!/usr/bin/env bash
# Run SAST scan with all tools. No container needed.
# Downloads missing tool binaries to ~/.cache/security-audit-tools/ on first run.
#
# Usage: scan_container.sh <org/repo> <branch> <results-dir>
set -euo pipefail

REPO="${1:?Usage: scan_container.sh <org/repo> <branch> <results-dir>}"
BRANCH="${2:-main}"
RESULTS_DIR="${3:?results-dir required}"
REPO_SHORT="${REPO##*/}"

RESULTS_DIR="$(mkdir -p "${RESULTS_DIR}" && cd "${RESULTS_DIR}" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Install missing tools (cached between runs)
source "${SCRIPT_DIR}/install_tools.sh"

# Clone and scan using scan-repo.sh from the scanner repo
# Check if scan-repo.sh is bundled with the skill
SCAN_SCRIPT=""
if [ -f "${SCRIPT_DIR}/../../scripts/scan-repo.sh" ]; then
  SCAN_SCRIPT="${SCRIPT_DIR}/../../scripts/scan-repo.sh"
elif [ -f "${SCRIPT_DIR}/scan-repo.sh" ]; then
  SCAN_SCRIPT="${SCRIPT_DIR}/scan-repo.sh"
fi

if [ -n "${SCAN_SCRIPT}" ]; then
  # Use the tuned scan-repo.sh with configs
  MOUNT_DIR="$(mktemp -d)"
  bash "${SCAN_SCRIPT}" "${REPO}" "${MOUNT_DIR}"
  if [ -d "${MOUNT_DIR}/${REPO_SHORT}" ]; then
    cp -R "${MOUNT_DIR}/${REPO_SHORT}/"* "${RESULTS_DIR}/" 2>/dev/null || true
  fi
  rm -rf "${MOUNT_DIR}"
else
  # Fallback: run tools directly (no scan-repo.sh)
  bash "${SCRIPT_DIR}/run_all.sh" "${REPO}" "${BRANCH}" "${RESULTS_DIR}"
fi

echo "Scan complete. Results in ${RESULTS_DIR}"
