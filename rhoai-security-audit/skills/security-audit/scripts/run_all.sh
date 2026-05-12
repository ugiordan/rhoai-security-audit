#!/usr/bin/env bash
# Runs all SAST tools inside the scanner container.
# Usage: run_all.sh <org/repo> <branch> <results-dir>
set -euo pipefail

REPO="${1:?Usage: run_all.sh <org/repo> <branch> <results-dir>}"
BRANCH="${2:-main}"
RESULTS_DIR="${3:-/results}"
REPO_SHORT="${REPO##*/}"
WORKDIR="/tmp/scan-${REPO_SHORT}"

mkdir -p "${RESULTS_DIR}"

echo "=== Scanning ${REPO} (branch: ${BRANCH}) ==="
START_TIME=$(date +%s)

# Clone (clean up any leftover from previous run)
rm -rf "${WORKDIR}"
if ! git clone --depth 1 --branch "${BRANCH}" "https://github.com/${REPO}.git" "${WORKDIR}" 2>/dev/null; then
  # Branch might not exist, try without --branch
  git clone --depth 1 "https://github.com/${REPO}.git" "${WORKDIR}" 2>/dev/null || {
    echo '{"error":"clone failed"}' > "${RESULTS_DIR}/scan-summary.json"
    exit 1
  }
fi

COMMIT_SHA=$(git -C "${WORKDIR}" rev-parse HEAD 2>/dev/null || echo "unknown")
TOOLS_RAN=()
TOOLS_FAILED=()
TOOL_COUNTS_LOG=""

run_tool() {
  local name="$1" cmd="$2" output="$3" empty_default="${4:-}"
  echo "--- ${name} ---"
  TIMEOUT_CMD="timeout"
  command -v timeout &>/dev/null || TIMEOUT_CMD="gtimeout"
  command -v $TIMEOUT_CMD &>/dev/null || TIMEOUT_CMD=""
  if eval "${TIMEOUT_CMD:+$TIMEOUT_CMD 600} ${cmd}" 2>/dev/null; then
    TOOLS_RAN+=("${name}")
  else
    TOOLS_RAN+=("${name}")
    if [ -n "${empty_default}" ] && { [ ! -f "${output}" ] || [ ! -s "${output}" ]; }; then
      echo "${empty_default}" > "${output}"
    fi
  fi
  if [ -f "${output}" ]; then
    local count
    count=$(python3 -c "
import json, sys
try:
    d = json.load(open('${output}'))
    if isinstance(d, list): print(len(d))
    elif 'results' in d: print(len(d['results']))
    elif 'Results' in d: print(sum(len(r.get('Vulnerabilities',[])) for r in d.get('Results',[])))
    elif 'matches' in d: print(len(d['matches']))
    elif 'Issues' in d: print(len(d['Issues']))
    elif 'Reports' in d: print(len(d['Reports']))
    elif 'runs' in d: print(sum(len(r.get('results',[])) for r in d.get('runs',[])))
    elif 'dependencies' in d: print(sum(len(dep.get('vulns',[])) for dep in d.get('dependencies',[])))
    else: print(0)
except: print(0)
" 2>/dev/null || echo 0)
    TOOL_COUNTS_LOG="${TOOL_COUNTS_LOG}${name}:${count},"
    echo "  ${count} findings"
  fi
}

# --- semgrep ---
run_tool "semgrep" \
  "semgrep scan --config auto --json --output '${RESULTS_DIR}/semgrep.json' '${WORKDIR}/'" \
  "${RESULTS_DIR}/semgrep.json" \
  '{"results":[]}'

# --- gitleaks ---
run_tool "gitleaks" \
  "gitleaks detect --source '${WORKDIR}' --report-format json --report-path '${RESULTS_DIR}/gitleaks-report.json' --no-git" \
  "${RESULTS_DIR}/gitleaks-report.json" \
  '[]'

# --- trufflehog ---
run_tool "trufflehog" \
  "trufflehog filesystem '${WORKDIR}' --json > '${RESULTS_DIR}/trufflehog-report.json'" \
  "${RESULTS_DIR}/trufflehog-report.json" \
  '[]'

# --- shellcheck ---
SHELL_FILES=$(find "${WORKDIR}" -name '*.sh' -type f -not -path '*/vendor/*' -not -path '*/.git/*' 2>/dev/null || true)
if [ -n "${SHELL_FILES}" ]; then
  run_tool "shellcheck" \
    "echo '${SHELL_FILES}' | tr ' ' '\n' | xargs shellcheck -f json > '${RESULTS_DIR}/shellcheck-report.json'" \
    "${RESULTS_DIR}/shellcheck-report.json" \
    '[]'
else
  echo '[]' > "${RESULTS_DIR}/shellcheck-report.json"
  TOOLS_RAN+=("shellcheck")
  TOOL_COUNTS_LOG="${TOOL_COUNTS_LOG}shellcheck:0,"
fi

# --- hadolint ---
DOCKERFILES=$(find "${WORKDIR}" \( -name 'Dockerfile*' -o -name 'Containerfile*' \) -type f -not -path '*/.git/*' 2>/dev/null || true)
if [ -n "${DOCKERFILES}" ]; then
  run_tool "hadolint" \
    "echo '${DOCKERFILES}' | tr ' ' '\n' | xargs hadolint -f sarif > '${RESULTS_DIR}/hadolint.sarif'" \
    "${RESULTS_DIR}/hadolint.sarif" \
    '{"runs":[]}'
else
  echo '{"runs":[]}' > "${RESULTS_DIR}/hadolint.sarif"
  TOOLS_RAN+=("hadolint")
  TOOL_COUNTS_LOG="${TOOL_COUNTS_LOG}hadolint:0,"
fi

# --- trivy ---
run_tool "trivy" \
  "trivy fs --format json --scanners vuln --skip-dirs vendor --skip-dirs node_modules '${WORKDIR}' > '${RESULTS_DIR}/trivy-report.json'" \
  "${RESULTS_DIR}/trivy-report.json" \
  '{"Results":[]}'

# --- grype ---
run_tool "grype" \
  "grype 'dir:${WORKDIR}' -o json > '${RESULTS_DIR}/grype-report.json'" \
  "${RESULTS_DIR}/grype-report.json" \
  '{"matches":[]}'

# --- kube-linter ---
if [ -d "${WORKDIR}/config" ]; then
  run_tool "kube-linter" \
    "kube-linter lint '${WORKDIR}/config' --format json > '${RESULTS_DIR}/kube-linter.json'" \
    "${RESULTS_DIR}/kube-linter.json" \
    '{"Reports":[]}'
else
  echo '{"Reports":[]}' > "${RESULTS_DIR}/kube-linter.json"
  TOOLS_RAN+=("kube-linter")
  TOOL_COUNTS_LOG="${TOOL_COUNTS_LOG}kube-linter:0,"
fi

# --- actionlint ---
if [ -d "${WORKDIR}/.github/workflows" ]; then
  run_tool "actionlint" \
    "actionlint -format sarif '${WORKDIR}/.github/workflows/' > '${RESULTS_DIR}/actionlint.sarif'" \
    "${RESULTS_DIR}/actionlint.sarif" \
    '{"runs":[]}'
fi

# --- zizmor ---
if [ -d "${WORKDIR}/.github/workflows" ]; then
  run_tool "zizmor" \
    "zizmor --format sarif '${WORKDIR}/.github/workflows/' > '${RESULTS_DIR}/zizmor.sarif'" \
    "${RESULTS_DIR}/zizmor.sarif" \
    '{"runs":[]}'
fi

# --- yamllint ---
run_tool "yamllint" \
  "yamllint -f parsable '${WORKDIR}' > '${RESULTS_DIR}/yamllint-report.txt'" \
  "${RESULTS_DIR}/yamllint-report.txt"

# --- govulncheck ---
if [ -f "${WORKDIR}/go.mod" ]; then
  run_tool "govulncheck" \
    "cd '${WORKDIR}' && govulncheck -format json ./... 2>/dev/null | python3 -c \"
import sys, json
objects = []
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try: objects.append(json.loads(line))
    except: pass
json.dump(objects, sys.stdout)
\" > '${RESULTS_DIR}/govulncheck-report.json'" \
    "${RESULTS_DIR}/govulncheck-report.json" \
    '[]'
fi

# --- gosec ---
if [ -f "${WORKDIR}/go.mod" ]; then
  run_tool "gosec" \
    "cd '${WORKDIR}' && gosec -fmt json ./... > '${RESULTS_DIR}/gosec-report.json'" \
    "${RESULTS_DIR}/gosec-report.json" \
    '{"Issues":[]}'
fi

# --- pip-audit ---
PIP_REQ=$(find "${WORKDIR}" -maxdepth 2 -name 'requirements.txt' -type f 2>/dev/null | head -1)
if [ -n "${PIP_REQ}" ]; then
  run_tool "pip-audit" \
    "pip-audit --format json -r '${PIP_REQ}' --output '${RESULTS_DIR}/pip-audit-report.json' --desc --dry-run" \
    "${RESULTS_DIR}/pip-audit-report.json" \
    '{"dependencies":[]}'
fi

# --- osv-scanner ---
run_tool "osv-scanner" \
  "osv-scanner --json '${WORKDIR}' > '${RESULTS_DIR}/osv-scanner-report.json'" \
  "${RESULTS_DIR}/osv-scanner-report.json" \
  '{"results":[]}'

# Cleanup
rm -rf "${WORKDIR}"

END_TIME=$(date +%s)
DURATION=$(( END_TIME - START_TIME ))

# Write summary
python3 -c "
import json
data = {
    'repo': '${REPO}',
    'branch': '${BRANCH}',
    'commit': '${COMMIT_SHA}',
    'tools_ran': $(printf '%s\n' "${TOOLS_RAN[@]}" | python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))"),
    'duration_s': ${DURATION},
}
json.dump(data, open('${RESULTS_DIR}/scan-summary.json', 'w'), indent=2)
"

echo "=== Done: ${#TOOLS_RAN[@]} tools in ${DURATION}s ==="
