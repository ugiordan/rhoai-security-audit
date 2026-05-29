#!/usr/bin/env bash
# Run SAST scan with all tools + tuned configs bundled in the skill.
# Downloads missing tool binaries on first run. No container needed.
#
# Usage: scan_container.sh <org/repo> <branch> <results-dir>
set -euo pipefail

REPO="${1:?Usage: scan_container.sh <org/repo> <branch> <results-dir>}"
BRANCH="${2:-main}"
RESULTS_DIR="${3:?results-dir required}"
REPO_SHORT="${REPO##*/}"

RESULTS_DIR="$(mkdir -p "${RESULTS_DIR}" && cd "${RESULTS_DIR}" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Install missing tools (cached between runs)
_SAVED_ARGS=("$@")
set --
source "${SCRIPT_DIR}/install_tools.sh"
set -- "${_SAVED_ARGS[@]}"

# Use scan-repo.sh bundled with the skill (includes tuned configs)
SCAN_SCRIPT="${SKILL_DIR}/scanner/scripts/scan-repo.sh"

if [ -f "${SCAN_SCRIPT}" ]; then
  MOUNT_DIR="$(mktemp -d)"
  SCAN_BRANCH="${BRANCH}" bash "${SCAN_SCRIPT}" "${REPO}" "${MOUNT_DIR}"
  if [ -d "${MOUNT_DIR}/${REPO_SHORT}" ]; then
    cp -R "${MOUNT_DIR}/${REPO_SHORT}/"* "${RESULTS_DIR}/" 2>/dev/null || true
  fi
  rm -rf "${MOUNT_DIR}"
else
  echo "WARNING: scan-repo.sh not found at ${SCAN_SCRIPT}. Using run_all.sh (no tuning)."
  bash "${SCRIPT_DIR}/run_all.sh" "${REPO}" "${BRANCH}" "${RESULTS_DIR}"
fi

echo "Scan complete. Results in ${RESULTS_DIR}"
