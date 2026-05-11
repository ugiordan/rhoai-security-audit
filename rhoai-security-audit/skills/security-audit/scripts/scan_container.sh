#!/usr/bin/env bash
# Host-side wrapper: runs SAST tools inside a container using scan-repo.sh
# with all the tuned configs from rhoai-security-scanner.
#
# The container bundles:
# - scan-repo.sh (the same script used by GHA workflows)
# - configs/ (semgrep rules, gitleaks ignore, kube-linter config, grype config, etc.)
# - All 15 SAST tools pre-installed
#
# Usage: scan_container.sh <org/repo> <branch> <results-dir>
set -euo pipefail

REPO="${1:?Usage: scan_container.sh <org/repo> <branch> <results-dir>}"
BRANCH="${2:-main}"
RESULTS_DIR="${3:?results-dir required}"
IMAGE="${SCANNER_IMAGE:-quay.io/ugiordan/security-audit-scanner:latest}"
REPO_SHORT="${REPO##*/}"

RESULTS_DIR="$(mkdir -p "${RESULTS_DIR}" && cd "${RESULTS_DIR}" && pwd)"

# Detect container runtime
RUNTIME=""
if command -v docker &>/dev/null; then
  RUNTIME="docker"
elif command -v podman &>/dev/null; then
  RUNTIME="podman"
fi

if [ -n "${RUNTIME}" ]; then
  echo "Running SAST scan in container (${RUNTIME}, image: ${IMAGE})"
  ${RUNTIME} pull "${IMAGE}" 2>/dev/null || true

  # scan-repo.sh writes to <results-base>/<repo-short>/
  # We mount the parent dir so scan-repo.sh can create the repo subdir
  RESULTS_PARENT="$(dirname "${RESULTS_DIR}")"
  RESULTS_BASE="$(basename "${RESULTS_DIR}")"

  ${RUNTIME} run --rm \
    -v "${RESULTS_DIR}:/results:z" \
    -w /scanner \
    "${IMAGE}" \
    "${REPO}" /results
  echo "Container scan complete. Results in ${RESULTS_DIR}"
else
  echo "WARNING: No container runtime (docker/podman) found."
  echo "Running with locally installed tools only. Some tools may be missing."
  echo "Install docker or podman for full 15-tool coverage."
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  bash "${SCRIPT_DIR}/run_all.sh" "${REPO}" "${BRANCH}" "${RESULTS_DIR}"
fi
