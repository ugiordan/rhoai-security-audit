#!/usr/bin/env bash
# Download SAST tool binaries to a local directory.
# Tools are cached between runs. No system modification.
#
# Usage: source install_tools.sh [tools-dir]
# After sourcing, PATH is updated and all tools are available.
set -euo pipefail

TOOLS_DIR="${1:-${HOME}/.cache/security-audit-tools}"
mkdir -p "${TOOLS_DIR}/bin"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

# Normalize arch names
case "${ARCH}" in
  x86_64|amd64) ARCH_GO="amd64"; ARCH_ALT="x64"; ARCH_TRIVY="64bit"; ARCH_SC="x86_64" ;;
  aarch64|arm64) ARCH_GO="arm64"; ARCH_ALT="arm64"; ARCH_TRIVY="ARM64"; ARCH_SC="aarch64" ;;
  *) echo "Unsupported arch: ${ARCH}"; exit 1 ;;
esac

case "${OS}" in
  linux) OS_TRIVY="Linux"; OS_HAD="Linux" ;;
  darwin) OS_TRIVY="macOS"; OS_HAD="Darwin" ;;
  *) echo "Unsupported OS: ${OS}"; exit 1 ;;
esac

BIN="${TOOLS_DIR}/bin"
INSTALLED=0
SKIPPED=0

_install() {
  local name="$1"
  if [ -f "${BIN}/${name}" ] && [ -x "${BIN}/${name}" ]; then
    SKIPPED=$((SKIPPED + 1))
    return 0
  fi
  INSTALLED=$((INSTALLED + 1))
}

echo "Installing SAST tools to ${TOOLS_DIR}..."

# --- semgrep (pip, uses venv to avoid system modification) ---
if ! command -v semgrep &>/dev/null && [ ! -f "${TOOLS_DIR}/venv/bin/semgrep" ]; then
  echo "  Installing semgrep via pip (venv)..."
  python3 -m venv "${TOOLS_DIR}/venv" 2>/dev/null || true
  "${TOOLS_DIR}/venv/bin/pip" install --quiet semgrep 2>/dev/null || true
  INSTALLED=$((INSTALLED + 1))
else
  SKIPPED=$((SKIPPED + 1))
fi

# --- gitleaks ---
_install gitleaks
if [ $? -eq 0 ] && [ ! -f "${BIN}/gitleaks" ]; then
  GITLEAKS_VERSION="8.30.0"
  curl -sSfL -o /tmp/gitleaks.tar.gz \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${OS}_${ARCH_ALT}.tar.gz"
  tar -xzf /tmp/gitleaks.tar.gz -C "${BIN}" gitleaks && rm /tmp/gitleaks.tar.gz
fi

# --- trufflehog ---
_install trufflehog
if [ ! -f "${BIN}/trufflehog" ]; then
  TRUFFLEHOG_VERSION="3.92.3"
  curl -sSfL -o /tmp/trufflehog.tar.gz \
    "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_${OS}_${ARCH_GO}.tar.gz"
  tar -xzf /tmp/trufflehog.tar.gz -C "${BIN}" trufflehog && rm /tmp/trufflehog.tar.gz
fi

# --- shellcheck ---
_install shellcheck
if [ ! -f "${BIN}/shellcheck" ]; then
  SHELLCHECK_VERSION="0.10.0"
  if [ "${OS}" = "darwin" ]; then
    curl -sSfL -o /tmp/sc.tar.xz \
      "https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK_VERSION}/shellcheck-v${SHELLCHECK_VERSION}.${OS}.${ARCH_SC}.tar.xz"
  else
    curl -sSfL -o /tmp/sc.tar.xz \
      "https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK_VERSION}/shellcheck-v${SHELLCHECK_VERSION}.${OS}.${ARCH_SC}.tar.xz"
  fi
  tar -xJf /tmp/sc.tar.xz -C /tmp/ && mv "/tmp/shellcheck-v${SHELLCHECK_VERSION}/shellcheck" "${BIN}/" && rm -rf /tmp/sc.tar.xz /tmp/shellcheck-*
fi

# --- hadolint ---
_install hadolint
if [ ! -f "${BIN}/hadolint" ]; then
  HADOLINT_VERSION="2.14.0"
  case "${OS}" in
    darwin) HAD_OS="macos" ;;
    linux) HAD_OS="linux" ;;
  esac
  case "${ARCH}" in
    x86_64|amd64) HAD_ARCH="x86_64" ;;
    aarch64|arm64) HAD_ARCH="arm64" ;;
  esac
  curl -sSfL -o "${BIN}/hadolint" \
    "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-${HAD_OS}-${HAD_ARCH}"
  chmod +x "${BIN}/hadolint"
fi

# --- trivy ---
_install trivy
if [ ! -f "${BIN}/trivy" ]; then
  TRIVY_VERSION="0.70.0"
  curl -sSfL -o /tmp/trivy.tar.gz \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${OS_TRIVY}-${ARCH_TRIVY}.tar.gz"
  tar -xzf /tmp/trivy.tar.gz -C "${BIN}" trivy && rm /tmp/trivy.tar.gz
fi

# --- grype (pinned, no curl|sh) ---
_install grype
if [ ! -f "${BIN}/grype" ]; then
  GRYPE_VERSION="0.112.0"
  curl -sSfL -o /tmp/grype.tar.gz \
    "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_${OS}_${ARCH_GO}.tar.gz"
  tar -xzf /tmp/grype.tar.gz -C "${BIN}" grype && rm /tmp/grype.tar.gz
fi

# --- kube-linter ---
_install kube-linter
if [ ! -f "${BIN}/kube-linter" ]; then
  KUBELINTER_VERSION="0.8.3"
  if [ "${OS}" = "darwin" ]; then KL_SUFFIX="${OS}"; else KL_SUFFIX="linux"; fi
  curl -sSfL -o /tmp/kl.tar.gz \
    "https://github.com/stackrox/kube-linter/releases/download/v${KUBELINTER_VERSION}/kube-linter-${KL_SUFFIX}.tar.gz"
  tar -xzf /tmp/kl.tar.gz -C "${BIN}" kube-linter && rm /tmp/kl.tar.gz
fi

# --- actionlint ---
_install actionlint
if [ ! -f "${BIN}/actionlint" ]; then
  ACTIONLINT_VERSION="1.7.8"
  curl -sSfL -o /tmp/al.tar.gz \
    "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_${OS}_${ARCH_GO}.tar.gz"
  tar -xzf /tmp/al.tar.gz -C "${BIN}" actionlint && rm /tmp/al.tar.gz
fi

# --- osv-scanner (pinned version) ---
_install osv-scanner
if [ ! -f "${BIN}/osv-scanner" ]; then
  OSV_VERSION="2.3.8"
  curl -sSfL -o "${BIN}/osv-scanner" \
    "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_${OS}_${ARCH_GO}"
  chmod +x "${BIN}/osv-scanner"
fi

# --- zizmor (pip) ---
if ! command -v zizmor &>/dev/null && [ ! -f "${TOOLS_DIR}/venv/bin/zizmor" ]; then
  echo "  Installing zizmor via pip..."
  [ -d "${TOOLS_DIR}/venv" ] || python3 -m venv "${TOOLS_DIR}/venv" 2>/dev/null || true
  "${TOOLS_DIR}/venv/bin/pip" install --quiet zizmor 2>/dev/null || true
fi

# --- yamllint (pip) ---
if ! command -v yamllint &>/dev/null && [ ! -f "${TOOLS_DIR}/venv/bin/yamllint" ]; then
  echo "  Installing yamllint via pip..."
  [ -d "${TOOLS_DIR}/venv" ] || python3 -m venv "${TOOLS_DIR}/venv" 2>/dev/null || true
  "${TOOLS_DIR}/venv/bin/pip" install --quiet yamllint 2>/dev/null || true
fi

# --- pip-audit (pip) ---
if ! command -v pip-audit &>/dev/null && [ ! -f "${TOOLS_DIR}/venv/bin/pip-audit" ]; then
  echo "  Installing pip-audit via pip..."
  [ -d "${TOOLS_DIR}/venv" ] || python3 -m venv "${TOOLS_DIR}/venv" 2>/dev/null || true
  "${TOOLS_DIR}/venv/bin/pip" install --quiet pip-audit 2>/dev/null || true
fi

# --- govulncheck (Go, only if Go is installed) ---
if command -v go &>/dev/null; then
  if ! command -v govulncheck &>/dev/null && [ ! -f "${BIN}/govulncheck" ]; then
    echo "  Installing govulncheck..."
    GOBIN="${BIN}" go install golang.org/x/vuln/cmd/govulncheck@v1.1.4 2>/dev/null || true
  fi
fi

# --- gosec (Go, only if Go is installed) ---
if command -v go &>/dev/null; then
  if ! command -v gosec &>/dev/null && [ ! -f "${BIN}/gosec" ]; then
    echo "  Installing gosec..."
    GOBIN="${BIN}" go install github.com/securego/gosec/v2/cmd/gosec@v2.22.4 2>/dev/null || true
  fi
fi

# Update PATH
export PATH="${BIN}:${TOOLS_DIR}/venv/bin:${PATH}"

echo "Done. ${INSTALLED} installed, ${SKIPPED} cached. Tools in ${TOOLS_DIR}"
