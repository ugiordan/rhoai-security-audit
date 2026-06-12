#!/usr/bin/env bash
# Scan a single repo using RHOAI security plugin configs.
# Usage: scan-repo.sh <org/repo> <results-base-dir>
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: $0 <org/repo> <results-base-dir> [tool1,tool2,...]" >&2
  exit 1
fi

REPO="$1"
RESULTS_BASE="$2"
TOOL_LIST="${3:-}"

# Tool selection: if a comma-separated list is provided as 3rd arg, only run those tools.
# Empty TOOL_LIST means run everything (backward compatible).
_should_run() {
  [ -z "${TOOL_LIST}" ] && return 0
  echo ",${TOOL_LIST}," | grep -q ",${1},"
}

# Validate repo format (org/name, alphanumeric with dots, hyphens, underscores)
if [[ ! "$REPO" =~ ^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$ ]]; then
  echo "ERROR: Invalid repo format '${REPO}'. Expected org/repo (e.g. opendatahub-io/kserve)" >&2
  exit 1
fi
SHORT="${REPO##*/}"
WORKDIR="repos/${SHORT}"
if [[ "${RESULTS_BASE}" = /* ]]; then
  OUTDIR="${RESULTS_BASE}/${SHORT}"
else
  OUTDIR="$(pwd)/${RESULTS_BASE}/${SHORT}"
fi

# Resolve configs directory relative to this script
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIGS_DIR="${SCRIPT_DIR}/../configs"

mkdir -p "${OUTDIR}"

echo "=== Scanning ${REPO} ==="

# Clone (use SCAN_BRANCH env var if set, otherwise default branch)
BRANCH_FLAG=""
if [ -n "${SCAN_BRANCH:-}" ]; then
  BRANCH_FLAG="--branch ${SCAN_BRANCH}"
fi
if [ -d "${WORKDIR}" ]; then
  rm -rf "${WORKDIR}"
fi
if ! git clone --depth 1 ${BRANCH_FLAG} "https://github.com/${REPO}.git" "${WORKDIR}" 2>/dev/null; then
  echo "ERROR: Failed to clone ${REPO}"
  echo '{"repo":"'"${REPO}"'","error":"clone failed"}' > "${OUTDIR}/security-summary.json"
  exit 1
fi

# Capture commit SHA and default branch for stable file permalinks in the dashboard
COMMIT_SHA=$(git -C "${WORKDIR}" rev-parse HEAD 2>/dev/null || echo "")
DEFAULT_BRANCH=$(git -C "${WORKDIR}" symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's|refs/remotes/origin/||' || echo "")
if [ -z "${DEFAULT_BRANCH}" ]; then
  # Fallback: use current branch name (shallow clones always check out default)
  DEFAULT_BRANCH=$(git -C "${WORKDIR}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
fi
echo "${COMMIT_SHA}" > "${OUTDIR}/commit-sha.txt"
python3 -c "
import json, sys
json.dump({'commit_sha': sys.argv[1], 'default_branch': sys.argv[2]}, open(sys.argv[3] + '/commit-info.json', 'w'))
" "${COMMIT_SHA}" "${DEFAULT_BRANCH}" "${OUTDIR}"

# --- gitleaks ---
if _should_run gitleaks; then
# Use centralized config for consistent false-positive suppression
GITLEAKS_ARGS=(detect --source "${WORKDIR}" --report-format json --report-path "${OUTDIR}/gitleaks-report.json" --no-git)
# Prefer centralized .gitleaks.toml (allowlist.paths) over repo-local config
if [ -f "${CONFIGS_DIR}/.gitleaks.toml" ]; then
  GITLEAKS_ARGS+=(-c "${CONFIGS_DIR}/.gitleaks.toml")
elif [ -f "${WORKDIR}/.gitleaks.toml" ]; then
  GITLEAKS_ARGS+=(-c "${WORKDIR}/.gitleaks.toml")
fi
# Also copy centralized .gitleaksignore for fingerprint-based suppression
if [ -f "${CONFIGS_DIR}/.gitleaksignore" ]; then
  cp "${CONFIGS_DIR}/.gitleaksignore" "${WORKDIR}/.gitleaksignore"
fi
timeout 300 gitleaks "${GITLEAKS_ARGS[@]}" 2>/dev/null || true
fi

# --- trufflehog ---
if _should_run trufflehog; then
TRUFFLEHOG_ARGS=(--json)
if [ -f "${CONFIGS_DIR}/.trufflehog-exclude" ]; then
  TRUFFLEHOG_ARGS+=(--exclude-paths="${CONFIGS_DIR}/.trufflehog-exclude")
fi
timeout 300 trufflehog filesystem "${WORKDIR}" "${TRUFFLEHOG_ARGS[@]}" > "${OUTDIR}/trufflehog-report.json" 2>/dev/null || true
fi

# --- semgrep ---
if _should_run semgrep; then
# Use the single unified config (covers Go, Python, TypeScript, YAML, Dockerfile, shell).
# Secret detection is handled by gitleaks/trufflehog, not semgrep.
SEMGREP_ARGS=()
if [ -f "${CONFIGS_DIR}/semgrep/semgrep-unified.yaml" ]; then
  SEMGREP_ARGS+=(--config "${CONFIGS_DIR}/semgrep/semgrep-unified.yaml")
else
  SEMGREP_ARGS+=(--config auto)
fi
# Exclude non-production paths to reduce noise
SEMGREP_EXCLUDES=(vendor node_modules dist build docs examples testdata __pycache__ .next
  test tests '*.pb.go' '*.pb.gw.go' 'zz_generated*' '*_generated.go' '*.md'
  benchmarks benchmark .buildkite .circleci tools ci hack contrib
  'scripts/templates' templates)
for excl in "${SEMGREP_EXCLUDES[@]}"; do
  SEMGREP_ARGS+=(--exclude "$excl")
done
timeout 600 semgrep scan "${SEMGREP_ARGS[@]}" --json --output "${OUTDIR}/semgrep.json" "${WORKDIR}/" 2>/dev/null || true

# Post-process: replace semgrep placeholder snippets with actual code from disk.
# Semgrep writes "requires login" when it can't capture the snippet itself.
# The repo is still on disk at this point, so we read the actual lines.
if [ -f "${OUTDIR}/semgrep.json" ]; then
  python3 -c "
import json, os, sys

MAX_LINES = 25
PLACEHOLDERS = {'requires login', ''}

with open(sys.argv[1]) as f:
    data = json.load(f)

patched = 0
for result in data.get('results', []):
    extra = result.get('extra', {})
    lines = extra.get('lines', '')
    if lines.strip() not in PLACEHOLDERS:
        continue

    path = result.get('path', '')
    start = result.get('start', {}).get('line')
    end = result.get('end', {}).get('line')
    if not start or not os.path.isfile(path):
        continue

    try:
        with open(path) as sf:
            all_lines = sf.readlines()
        actual_end = min(end or start, start + MAX_LINES - 1, len(all_lines))
        snippet = ''.join(all_lines[start - 1:actual_end])
        if actual_end < (end or start):
            snippet += f'  // ... ({(end or start) - actual_end} more lines)\n'
        extra['lines'] = snippet
        patched += 1
    except (OSError, IndexError):
        pass

with open(sys.argv[1], 'w') as f:
    json.dump(data, f, indent=2)

if patched > 0:
    print(f'  Patched {patched} semgrep snippets with actual code')
" "${OUTDIR}/semgrep.json" 2>/dev/null || true
fi
fi

# --- shellcheck ---
if _should_run shellcheck; then
# Exclude style/info rules that are not security-relevant:
#   SC2086 (word splitting) SC2155 (declare+assign) SC2034 (unused var)
#   SC2148 (missing shebang) SC1091 (not following sourced file)
#   SC2181 (check exit code directly) SC2006 (use $() not backticks)
#   SC2004 (unnecessary $ in arithmetic) SC2001 (use ${var//} not sed)
#   SC2002 (useless cat) SC2005 (useless echo) SC2116 (useless echo in $())
#   SC2012 (use find not ls) SC2015 (A&&B||C not if-then-else)
#   SC2028 (echo won't expand escapes) SC2162 (read -r)
SHELL_FILES=$(find "${WORKDIR}" -name '*.sh' -type f \
  -not -path '*/vendor/*' \
  -not -path '*/test/*' -not -path '*/tests/*' -not -path '*/testdata/*' \
  -not -path '*/examples/*' -not -path '*/docs/*' \
  -not -path '*/dist/*' -not -path '*/build/*' \
  -not -path '*/.git/*' -not -path '*/node_modules/*' \
  -not -path '*/.buildkite/*' -not -path '*/benchmarks/*' -not -path '*/benchmark/*' \
  -not -path '*/tools/*' -not -path '*/ci/*' -not -path '*/hack/*' \
  -not -path '*/contrib/*' -not -path '*/.circleci/*' 2>/dev/null)
if [ -n "${SHELL_FILES}" ]; then
  echo "${SHELL_FILES}" | xargs timeout 120 shellcheck -f json \
    --severity=warning \
    --exclude=SC2155,SC2034,SC2148,SC1091,SC2086,SC2181,SC2006,SC2004,SC2001,SC2002,SC2005,SC2116,SC2012,SC2015,SC2028,SC2162 \
    > "${OUTDIR}/shellcheck-report.json" 2>/dev/null || true
else
  echo "[]" > "${OUTDIR}/shellcheck-report.json"
fi
fi

# --- hadolint ---
if _should_run hadolint; then
# Ignore non-security rules:
#   DL3059 (multiple consecutive RUN), DL3008 (pin apt versions), DL3041 (pin dnf versions)
#   DL3001 (pointless commands), DL3003 (use WORKDIR not cd), DL3006 (tag image in FROM)
#   DL3009 (delete apt lists), DL3010 (use ADD for archives), DL3019 (use --no-cache)
#   DL3025 (use JSON for CMD), DL4006 (set -o pipefail)
DOCKERFILES=$(find "${WORKDIR}" \( -name 'Dockerfile*' -o -name 'Containerfile*' \) -type f \
  -not -path '*/examples/*' -not -path '*/tests/*' -not -path '*/testdata/*' \
  -not -path '*/docs/*' -not -path '*/dist/*' -not -path '*/vendor/*' \
  -not -path '*/.buildkite/*' -not -path '*/benchmarks/*' -not -path '*/benchmark/*' \
  -not -path '*/tools/*' -not -path '*/ci/*' -not -path '*/hack/*' \
  -not -path '*/contrib/*' -not -path '*/.circleci/*' 2>/dev/null)
if [ -n "${DOCKERFILES}" ]; then
  echo "${DOCKERFILES}" | xargs timeout 120 hadolint -f sarif \
    --ignore DL3059 --ignore DL3008 --ignore DL3041 \
    --ignore DL3001 --ignore DL3003 --ignore DL3006 \
    --ignore DL3009 --ignore DL3010 --ignore DL3019 \
    --ignore DL3025 --ignore DL4006 \
    > "${OUTDIR}/hadolint.sarif" 2>/dev/null || true
else
  echo '{"runs":[]}' > "${OUTDIR}/hadolint.sarif"
fi
fi

# --- yamllint ---
if _should_run yamllint; then
# Use centralized config (security-relevant rules only, no formatting noise)
# Only scan production YAML directories, not docs/examples/vendor/test
YAMLLINT_ARGS=()
if [ -f "${CONFIGS_DIR}/.yamllint.yaml" ]; then
  YAMLLINT_ARGS+=(-c "${CONFIGS_DIR}/.yamllint.yaml")
elif [ -f "${WORKDIR}/.yamllint.yaml" ]; then
  YAMLLINT_ARGS+=(-c "${WORKDIR}/.yamllint.yaml")
elif [ -f "${WORKDIR}/.yamllint.yml" ]; then
  YAMLLINT_ARGS+=(-c "${WORKDIR}/.yamllint.yml")
elif [ -f "${WORKDIR}/.yamllint" ]; then
  YAMLLINT_ARGS+=(-c "${WORKDIR}/.yamllint")
fi
YAML_DIRS=()
for dir in config deploy manifests charts .github/workflows; do
  if [ -d "${WORKDIR}/${dir}" ]; then
    YAML_DIRS+=("${WORKDIR}/${dir}")
  fi
done
if [ ${#YAML_DIRS[@]} -gt 0 ]; then
  timeout 120 yamllint "${YAMLLINT_ARGS[@]}" -f parsable "${YAML_DIRS[@]}" > "${OUTDIR}/yamllint-report.txt" 2>&1 || true
else
  echo "" > "${OUTDIR}/yamllint-report.txt"
fi
fi

# --- actionlint ---
if _should_run actionlint; then
if [ -d "${WORKDIR}/.github/workflows" ]; then
  # Disable built-in shellcheck integration (we run shellcheck separately)
  : > "${OUTDIR}/actionlint.txt"
  for ext in yml yaml; do
    shopt -s nullglob
    WORKFLOW_FILES=("${WORKDIR}"/.github/workflows/*.${ext})
    shopt -u nullglob
    if [ ${#WORKFLOW_FILES[@]} -gt 0 ]; then
      timeout 60 actionlint -shellcheck="" "${WORKFLOW_FILES[@]}" >> "${OUTDIR}/actionlint.txt" 2>&1 || true
    fi
  done
else
  echo "No workflows directory found" > "${OUTDIR}/actionlint.txt"
fi
fi

# --- zizmor (GitHub Actions security linter) ---
if _should_run zizmor; then
if [ -d "${WORKDIR}/.github/workflows" ]; then
  ZIZMOR_ARGS=(--format sarif)
  if [ -f "${CONFIGS_DIR}/.zizmor.yml" ]; then
    ZIZMOR_ARGS+=(-c "${CONFIGS_DIR}/.zizmor.yml")
  fi
  if [ -z "${GITHUB_TOKEN:-}" ]; then
    ZIZMOR_ARGS+=(--offline)
  fi
  timeout 120 zizmor "${ZIZMOR_ARGS[@]}" "${WORKDIR}/.github/workflows/" > "${OUTDIR}/zizmor.sarif" 2>/dev/null || true
else
  echo '{"runs":[]}' > "${OUTDIR}/zizmor.sarif"
fi
fi

# --- kustomize build (render manifests for accurate scanning) ---
# Restores feature parity with the in-repo security-full-scan.yml workflow.
# Rendered output is scanned by kube-linter alongside raw manifests.
if _should_run kube-linter; then
KUSTOMIZE_DIRS=()
for kdir in config/manifests config/default; do
  if [ -f "${WORKDIR}/${kdir}/kustomization.yaml" ] || [ -f "${WORKDIR}/${kdir}/kustomization.yml" ]; then
    KUSTOMIZE_DIRS+=("${kdir}")
  fi
done
if [ ${#KUSTOMIZE_DIRS[@]} -gt 0 ]; then
  mkdir -p "${WORKDIR}/_rendered"
  for kdir in "${KUSTOMIZE_DIRS[@]}"; do
    rendered_name=$(echo "${kdir}" | tr '/' '-')
    timeout 120 kustomize build "${WORKDIR}/${kdir}" > "${WORKDIR}/_rendered/${rendered_name}.yaml" 2>/dev/null || true
  done
fi

# --- kube-linter ---
# Use centralized kube-linter config (36 checks including custom CEL rules)
KUBE_DIRS=()
for dir in config deploy manifests charts; do
  if [ -d "${WORKDIR}/${dir}" ]; then
    KUBE_DIRS+=("${WORKDIR}/${dir}")
  fi
done
# Include kustomize-rendered manifests if available
if [ -d "${WORKDIR}/_rendered" ]; then
  KUBE_DIRS+=("${WORKDIR}/_rendered")
fi
if [ ${#KUBE_DIRS[@]} -gt 0 ]; then
  CONFIG_ARGS=()
  if [ -f "${CONFIGS_DIR}/.kube-linter.yaml" ]; then
    CONFIG_ARGS=(--config "${CONFIGS_DIR}/.kube-linter.yaml")
  elif [ -f "${WORKDIR}/.kube-linter.yaml" ]; then
    CONFIG_ARGS=(--config "${WORKDIR}/.kube-linter.yaml")
  fi
  # v0.8.3+ supports multi-format output in a single run (stackrox/kube-linter#1094)
  timeout 120 kube-linter lint "${KUBE_DIRS[@]}" "${CONFIG_ARGS[@]}" \
    --format json --output "${OUTDIR}/kube-linter.json" \
    --format sarif --output "${OUTDIR}/kube-linter.sarif" \
    2>/dev/null || true
else
  echo '{"Reports":[]}' > "${OUTDIR}/kube-linter.json"
  echo '{"runs":[]}'    > "${OUTDIR}/kube-linter.sarif"
fi
fi

# --- RBAC Analyzer ---
if _should_run rbac-analyzer; then
RBAC_DIRS=()
for dir in config deploy manifests charts; do
  if [ -d "${WORKDIR}/${dir}" ]; then
    RBAC_DIRS+=("${WORKDIR}/${dir}")
  fi
done
if [ ${#RBAC_DIRS[@]} -gt 0 ]; then
  timeout 120 python3 "${SCRIPT_DIR}/rbac-analyzer.py" "${RBAC_DIRS[@]}" --output-json "${OUTDIR}/rbac-analysis.json" 2>/dev/null || true
else
  echo '{"findings":[]}' > "${OUTDIR}/rbac-analysis.json"
fi
fi

# --- pip-audit (Python dependency vulnerability scanner) ---
if _should_run pip-audit; then
PIP_REQ_FILES=$(find "${WORKDIR}" -maxdepth 3 \( -name 'requirements.txt' -o -name 'requirements*.txt' \) \
  -not -path '*/vendor/*' -not -path '*/.tox/*' \
  -not -path '*/tests/*' -not -path '*/test/*' -not -path '*/examples/*' \
  -type f 2>/dev/null)
if [ -n "${PIP_REQ_FILES}" ]; then
  # Merge all requirements files, deduplicate, scan once
  PIP_AUDIT_TMP=$(mktemp /tmp/pip-audit-reqs.XXXXXX)
  echo "${PIP_REQ_FILES}" | xargs cat | sort -u > "${PIP_AUDIT_TMP}"
  timeout 300 pip-audit -r "${PIP_AUDIT_TMP}" --format json --output "${OUTDIR}/pip-audit-report.json" \
    --desc --fix --dry-run 2>/dev/null || true
  rm -f "${PIP_AUDIT_TMP}"
else
  # Check for pyproject.toml or setup.py as fallback
  if [ -f "${WORKDIR}/pyproject.toml" ] || [ -f "${WORKDIR}/setup.py" ]; then
    (cd "${WORKDIR}" && timeout 300 pip-audit --format json --output "${OUTDIR}/pip-audit-report.json" \
      --desc --fix --dry-run 2>/dev/null || true)
  else
    echo '{"dependencies":[]}' > "${OUTDIR}/pip-audit-report.json"
  fi
fi
fi

# --- govulncheck (Go module vulnerability scanner) ---
if _should_run govulncheck; then
if [ -f "${WORKDIR}/go.mod" ]; then
  # govulncheck -format json outputs newline-delimited JSON objects, not a valid JSON array.
  # Wrap them into an array so downstream parsers (dashboard ingestor) can json.load() it.
  (cd "${WORKDIR}" && timeout 300 govulncheck -format json ./... 2>/dev/null | python3 -c "
import sys, json
objects = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        objects.append(json.loads(line))
    except json.JSONDecodeError:
        pass
json.dump(objects, sys.stdout, indent=2)
" > "${OUTDIR}/govulncheck-report.json" || true)
  # Ensure valid JSON even if govulncheck or python3 failed
  if [ ! -s "${OUTDIR}/govulncheck-report.json" ] || ! python3 -c "import json,sys; json.load(open(sys.argv[1]))" "${OUTDIR}/govulncheck-report.json" 2>/dev/null; then
    echo '[]' > "${OUTDIR}/govulncheck-report.json"
  fi
else
  echo '[]' > "${OUTDIR}/govulncheck-report.json"
fi
fi

# --- trivy (multi-language SCA) ---
if _should_run trivy; then
timeout 600 trivy fs --format json --scanners vuln \
  --skip-dirs vendor --skip-dirs node_modules --skip-dirs dist --skip-dirs build \
  --skip-dirs test --skip-dirs tests --skip-dirs testdata --skip-dirs docs \
  "${WORKDIR}" > "${OUTDIR}/trivy-report.json" 2>/dev/null || true
if [ ! -s "${OUTDIR}/trivy-report.json" ]; then
  echo '{"Results":[]}' > "${OUTDIR}/trivy-report.json"
fi
fi

# --- grype (multi-language SCA, Anchore feed) ---
if _should_run grype; then
GRYPE_ARGS=(-o json)
GRYPE_ARGS+=(--exclude './vendor/**' --exclude './node_modules/**')
GRYPE_ARGS+=(--exclude './dist/**' --exclude './build/**')
GRYPE_ARGS+=(--exclude './test/**' --exclude './tests/**' --exclude './testdata/**')
GRYPE_ARGS+=(--exclude './docs/**' --exclude './examples/**')
if [ -f "${CONFIGS_DIR}/.grype.yaml" ]; then
  GRYPE_ARGS+=(-c "${CONFIGS_DIR}/.grype.yaml")
fi
timeout 600 grype "dir:${WORKDIR}" "${GRYPE_ARGS[@]}" > "${OUTDIR}/grype-report.json" 2>/dev/null || true
if [ ! -s "${OUTDIR}/grype-report.json" ]; then
  echo '{"matches":[]}' > "${OUTDIR}/grype-report.json"
fi
fi

# --- osv-scanner (Google OSV database) ---
if _should_run osv-scanner; then
OSV_ARGS=(scan source -r --format json)
OSV_ARGS+=(--experimental-exclude=vendor --experimental-exclude=node_modules)
OSV_ARGS+=(--experimental-exclude=dist --experimental-exclude=build)
OSV_ARGS+=(--experimental-exclude=test --experimental-exclude=tests)
OSV_ARGS+=(--experimental-exclude=testdata --experimental-exclude=docs)
OSV_ARGS+=(--experimental-exclude=examples)
if [ -f "${CONFIGS_DIR}/osv-scanner.toml" ]; then
  OSV_ARGS+=(--config="${CONFIGS_DIR}/osv-scanner.toml")
fi
timeout 600 osv-scanner "${OSV_ARGS[@]}" "${WORKDIR}" > "${OUTDIR}/osv-scanner-report.json" 2>/dev/null || true
if [ ! -s "${OUTDIR}/osv-scanner-report.json" ]; then
  echo '{"results":[]}' > "${OUTDIR}/osv-scanner-report.json"
fi
fi

# --- cppcheck (C/C++ static analysis) ---
# Detect C/C++ files once, used by both cppcheck and flawfinder
C_FILES=$(find "${WORKDIR}" \( -name '*.c' -o -name '*.h' -o -name '*.cpp' -o -name '*.cc' -o -name '*.cxx' -o -name '*.hpp' \) -type f \
  -not -path '*/vendor/*' -not -path '*/test/*' -not -path '*/tests/*' \
  -not -path '*/testdata/*' -not -path '*/examples/*' -not -path '*/docs/*' \
  -not -path '*/.git/*' -not -path '*/build/*' -not -path '*/node_modules/*' \
  -not -path '*/.buildkite/*' -not -path '*/benchmarks/*' -not -path '*/benchmark/*' \
  -not -path '*/tools/*' -not -path '*/ci/*' -not -path '*/hack/*' \
  -not -path '*/contrib/*' -not -path '*/.circleci/*' 2>/dev/null | head -1)

if _should_run cppcheck; then
if [ -n "${C_FILES}" ]; then
  echo "  [cppcheck] C/C++ files detected, running cppcheck..."
  timeout 600 cppcheck --xml --enable=warning,style,performance,portability \
    --suppress=missingInclude --suppress=unmatchedSuppression \
    --force --jobs=$(nproc 2>/dev/null || echo 4) \
    "${WORKDIR}" 2> "${OUTDIR}/cppcheck-report.xml" || true
  # Ensure valid XML even on failure
  if [ ! -s "${OUTDIR}/cppcheck-report.xml" ]; then
    echo '<?xml version="1.0"?><results version="2"><errors/></results>' > "${OUTDIR}/cppcheck-report.xml"
  fi
else
  echo '<?xml version="1.0"?><results version="2"><errors/></results>' > "${OUTDIR}/cppcheck-report.xml"
fi
fi

# --- flawfinder (C/C++ security-focused scanner) ---
if _should_run flawfinder; then
if [ -n "${C_FILES}" ]; then
  echo "  [flawfinder] Running flawfinder..."
  timeout 300 flawfinder --csv --columns --minlevel 3 "${WORKDIR}" > "${OUTDIR}/flawfinder-report.csv" 2>/dev/null || true
  # Ensure file exists even on failure
  if [ ! -f "${OUTDIR}/flawfinder-report.csv" ]; then
    echo "" > "${OUTDIR}/flawfinder-report.csv"
  fi
else
  echo "" > "${OUTDIR}/flawfinder-report.csv"
fi
fi

# --- Cleanup cloned repo to save disk ---
rm -rf "${WORKDIR}"

# --- Create per-repo security summary ---
SCAN_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

GITLEAKS_COUNT=0
if [ -f "${OUTDIR}/gitleaks-report.json" ]; then
  GITLEAKS_COUNT=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(len(d) if isinstance(d,list) else 0)" "${OUTDIR}/gitleaks-report.json" 2>/dev/null || echo 0)
fi

TRUFFLEHOG_COUNT=0
if [ -f "${OUTDIR}/trufflehog-report.json" ]; then
  TRUFFLEHOG_COUNT=$(grep -c '^{' "${OUTDIR}/trufflehog-report.json" 2>/dev/null || echo 0)
fi

SEMGREP_COUNT=0
if [ -f "${OUTDIR}/semgrep.json" ]; then
  SEMGREP_COUNT=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(len(d.get('results',[])))" "${OUTDIR}/semgrep.json" 2>/dev/null || echo 0)
fi

SHELLCHECK_COUNT=0
if [ -f "${OUTDIR}/shellcheck-report.json" ]; then
  SHELLCHECK_COUNT=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(len(d) if isinstance(d,list) else 0)" "${OUTDIR}/shellcheck-report.json" 2>/dev/null || echo 0)
fi

HADOLINT_COUNT=0
if [ -f "${OUTDIR}/hadolint.sarif" ]; then
  HADOLINT_COUNT=$(python3 -c "
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    total=sum(len(r.get('results',[])) for r in d.get('runs',[]))
    print(total)
except: print(0)
" "${OUTDIR}/hadolint.sarif" 2>/dev/null || echo 0)
fi

YAMLLINT_COUNT=0
if [ -f "${OUTDIR}/yamllint-report.txt" ]; then
  YAMLLINT_COUNT=$(grep -c ':' "${OUTDIR}/yamllint-report.txt" 2>/dev/null || echo 0)
fi

ACTIONLINT_COUNT=0
if [ -f "${OUTDIR}/actionlint.txt" ]; then
  ACTIONLINT_COUNT=$(grep -cv '^$\|^No workflows' "${OUTDIR}/actionlint.txt" 2>/dev/null || echo 0)
fi

KUBELINTER_COUNT=0
if [ -f "${OUTDIR}/kube-linter.json" ]; then
  KUBELINTER_COUNT=$(python3 -c "
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    print(len(d.get('Reports',[])))
except: print(0)
" "${OUTDIR}/kube-linter.json" 2>/dev/null || echo 0)
fi

ZIZMOR_COUNT=0
if [ -f "${OUTDIR}/zizmor.sarif" ]; then
  ZIZMOR_COUNT=$(python3 -c "
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    total=sum(len(r.get('results',[])) for r in d.get('runs',[]))
    print(total)
except: print(0)
" "${OUTDIR}/zizmor.sarif" 2>/dev/null || echo 0)
fi

RBAC_COUNT=0
if [ -f "${OUTDIR}/rbac-analysis.json" ]; then
  RBAC_COUNT=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(len(d.get('findings',[])))" "${OUTDIR}/rbac-analysis.json" 2>/dev/null || echo 0)
fi

PIPAUDIT_COUNT=0
if [ -f "${OUTDIR}/pip-audit-report.json" ]; then
  PIPAUDIT_COUNT=$(python3 -c "
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    total=sum(len(dep.get('vulns',[])) for dep in d.get('dependencies',[]))
    print(total)
except: print(0)
" "${OUTDIR}/pip-audit-report.json" 2>/dev/null || echo 0)
fi

GOVULNCHECK_COUNT=0
if [ -f "${OUTDIR}/govulncheck-report.json" ]; then
  GOVULNCHECK_COUNT=$(python3 -c "
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    if isinstance(d, list):
        # New format: array of NDJSON objects, count entries with 'finding' key (actual vulns)
        print(sum(1 for obj in d if 'finding' in obj))
    else:
        # Legacy format: dict with vulns key
        vulns=d.get('vulns',d.get('Vulns',[]))
        print(len(vulns) if vulns else 0)
except: print(0)
" "${OUTDIR}/govulncheck-report.json" 2>/dev/null || echo 0)
fi

TRIVY_COUNT=0
if [ -f "${OUTDIR}/trivy-report.json" ]; then
  TRIVY_COUNT=$(python3 -c "
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    total=sum(len(r.get('Vulnerabilities',[])) for r in d.get('Results',[]))
    print(total)
except: print(0)
" "${OUTDIR}/trivy-report.json" 2>/dev/null || echo 0)
fi

GRYPE_COUNT=0
if [ -f "${OUTDIR}/grype-report.json" ]; then
  GRYPE_COUNT=$(python3 -c "
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    print(len(d.get('matches',[])))
except: print(0)
" "${OUTDIR}/grype-report.json" 2>/dev/null || echo 0)
fi

OSV_COUNT=0
if [ -f "${OUTDIR}/osv-scanner-report.json" ]; then
  OSV_COUNT=$(python3 -c "
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    total=sum(len(p.get('vulnerabilities',[])) for r in d.get('results',[]) for p in r.get('packages',[]))
    print(total)
except: print(0)
" "${OUTDIR}/osv-scanner-report.json" 2>/dev/null || echo 0)
fi

CPPCHECK_COUNT=0
if [ -f "${OUTDIR}/cppcheck-report.xml" ]; then
  CPPCHECK_COUNT=$(python3 -c "
import xml.etree.ElementTree as ET, sys
try:
    tree = ET.parse(sys.argv[1])
    print(len([e for e in tree.getroot().iter('error') if e.get('id') not in ('missingInclude','unmatchedSuppression','toomanyconfigs')]))
except: print(0)
" "${OUTDIR}/cppcheck-report.xml" 2>/dev/null || echo 0)
fi

FLAWFINDER_COUNT=0
if [ -f "${OUTDIR}/flawfinder-report.csv" ] && [ -s "${OUTDIR}/flawfinder-report.csv" ]; then
  FLAWFINDER_COUNT=$(tail -n +2 "${OUTDIR}/flawfinder-report.csv" | grep -c '.' 2>/dev/null || echo 0)
fi

export REPO SCAN_DATE OUTDIR
export GITLEAKS_COUNT TRUFFLEHOG_COUNT SEMGREP_COUNT SHELLCHECK_COUNT
export HADOLINT_COUNT YAMLLINT_COUNT ACTIONLINT_COUNT ZIZMOR_COUNT KUBELINTER_COUNT
export RBAC_COUNT PIPAUDIT_COUNT GOVULNCHECK_COUNT TRIVY_COUNT GRYPE_COUNT OSV_COUNT CPPCHECK_COUNT FLAWFINDER_COUNT

python3 -c "
import json, os
def safe_int(v):
    try: return int(str(v).strip())
    except: return 0
data = {
    'repo': os.environ.get('REPO', ''),
    'scan_date': os.environ.get('SCAN_DATE', ''),
    'findings': {
        'gitleaks': safe_int(os.environ.get('GITLEAKS_COUNT', 0)),
        'trufflehog': safe_int(os.environ.get('TRUFFLEHOG_COUNT', 0)),
        'semgrep': safe_int(os.environ.get('SEMGREP_COUNT', 0)),
        'shellcheck': safe_int(os.environ.get('SHELLCHECK_COUNT', 0)),
        'hadolint': safe_int(os.environ.get('HADOLINT_COUNT', 0)),
        'yamllint': safe_int(os.environ.get('YAMLLINT_COUNT', 0)),
        'actionlint': safe_int(os.environ.get('ACTIONLINT_COUNT', 0)),
        'kube_linter': safe_int(os.environ.get('KUBELINTER_COUNT', 0)),
        'zizmor': safe_int(os.environ.get('ZIZMOR_COUNT', 0)),
        'rbac_analyzer': safe_int(os.environ.get('RBAC_COUNT', 0)),
        'pip_audit': safe_int(os.environ.get('PIPAUDIT_COUNT', 0)),
        'govulncheck': safe_int(os.environ.get('GOVULNCHECK_COUNT', 0)),
        'trivy': safe_int(os.environ.get('TRIVY_COUNT', 0)),
        'grype': safe_int(os.environ.get('GRYPE_COUNT', 0)),
        'osv_scanner': safe_int(os.environ.get('OSV_COUNT', 0)),
        'cppcheck': safe_int(os.environ.get('CPPCHECK_COUNT', 0)),
        'flawfinder': safe_int(os.environ.get('FLAWFINDER_COUNT', 0))
    }
}
json.dump(data, open(os.path.join(os.environ['OUTDIR'], 'security-summary.json'), 'w'), indent=2)
"

echo "=== Done scanning ${REPO} ==="
