#!/usr/bin/env bash
# Scan a container image for vulnerabilities using trivy and grype.
# Usage: scan-images.sh <image-ref> <results-base-dir>
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: $0 <image-ref> <results-base-dir>" >&2
  exit 1
fi

IMAGE_REF="$1"
RESULTS_BASE="$2"

# Extract short name from image ref (e.g., registry.redhat.io/rhoai/odh-vllm-gaudi-rhel9:latest -> odh-vllm-gaudi-rhel9)
SHORT=$(echo "${IMAGE_REF}" | sed 's|.*/||' | sed 's|:.*||')

if [[ "${RESULTS_BASE}" = /* ]]; then
  OUTDIR="${RESULTS_BASE}/${SHORT}"
else
  OUTDIR="$(pwd)/${RESULTS_BASE}/${SHORT}"
fi

mkdir -p "${OUTDIR}"

echo "=== Scanning image: ${IMAGE_REF} ==="

# Save image metadata using python for safe JSON construction
python3 -c "
import json, sys
json.dump({'image': sys.argv[1], 'short_name': sys.argv[2], 'scanned_at': sys.argv[3]}, open(sys.argv[4], 'w'))
" "${IMAGE_REF}" "${SHORT}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${OUTDIR}/image-info.json"

TRIVY_OK=0
GRYPE_OK=0

# Trivy image scan
if command -v trivy &>/dev/null; then
  echo "  Running trivy image..."
  if timeout 600 trivy image --format json --scanners vuln \
    --skip-dirs /usr/share/doc --skip-dirs /usr/share/man \
    "${IMAGE_REF}" > "${OUTDIR}/trivy-image-report.json" 2>/dev/null; then
    TRIVY_COUNT=$(python3 -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(sum(len(r.get('Vulnerabilities') or []) for r in d.get('Results', [])))
except: print(0)
" "${OUTDIR}/trivy-image-report.json" 2>/dev/null || echo 0)
    echo "  trivy: ${TRIVY_COUNT} vulnerabilities"
    TRIVY_OK=1
  else
    echo "  trivy: scan failed or timed out"
    echo '{}' > "${OUTDIR}/trivy-image-report.json"
  fi
else
  echo "  trivy: not installed, skipping"
fi

# Grype image scan
if command -v grype &>/dev/null; then
  echo "  Running grype..."
  if timeout 600 grype "${IMAGE_REF}" -o json \
    > "${OUTDIR}/grype-image-report.json" 2>/dev/null; then
    GRYPE_COUNT=$(python3 -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(len(d.get('matches', [])))
except: print(0)
" "${OUTDIR}/grype-image-report.json" 2>/dev/null || echo 0)
    echo "  grype: ${GRYPE_COUNT} vulnerabilities"
    GRYPE_OK=1
  else
    echo "  grype: scan failed or timed out"
    echo '{}' > "${OUTDIR}/grype-image-report.json"
  fi
else
  echo "  grype: not installed, skipping"
fi

# Summary using python for safe JSON construction
python3 -c "
import json, sys
json.dump({
    'image': sys.argv[1], 'short_name': sys.argv[2],
    'trivy_ok': int(sys.argv[3]), 'grype_ok': int(sys.argv[4]),
    'scanned_at': sys.argv[5],
}, open(sys.argv[6], 'w'), indent=2)
" "${IMAGE_REF}" "${SHORT}" "${TRIVY_OK}" "${GRYPE_OK}" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${OUTDIR}/security-summary.json"

echo "=== Done: ${SHORT} ==="
