---
name: security-audit
description: Runs 15 SAST tools and AI security skills against repositories, normalizes outputs, deduplicates findings, generates consolidated markdown + HTML reports with trend tracking. Use when asked to scan repos, generate security reports, check vulnerabilities, review security posture, or track security trends.
---

# Security Audit

This skill runs a fixed pipeline. You are an executor: run each step
in order and dispatch AI skills as instructed. Do not skip steps.

## Run exactly these steps

```
Pipeline:
- [ ] Step 1: Init session log
- [ ] Step 2: Run SAST scan (background)
- [ ] Step 3: Invoke AI skills
- [ ] Step 4: Wait for SAST, normalize, deduplicate
- [ ] Step 5: Generate ALL THREE reports
- [ ] Step 6: Update trends and finalize
```

**Step 1: Init**

```bash
DATE=$(date -u +%Y-%m-%d)
REPO_SHORT="${REPO##*/}"
OUTPUT_DIR="output/${REPO_SHORT}/${DATE}"
mkdir -p "${OUTPUT_DIR}/raw"
python3 ${CLAUDE_SKILL_DIR}/scripts/session_log.py init --repo "${REPO}" --output-dir "${OUTPUT_DIR}"
```

Parse JSON output. Store `session_file`.

**Step 2: SAST scan (run in background)**

```bash
bash ${CLAUDE_SKILL_DIR}/scripts/scan_container.sh "${REPO}" main "${OUTPUT_DIR}/raw"
```

Use `run_in_background: true`. This installs tools on first run
(~2 min), then scans (~30s). Do not wait for it.

**Step 3: Invoke AI skills**

While SAST runs, invoke AI skills. Skip ONLY if `--skip-ai` flag
was explicitly passed.

Check if pre-generated architecture context exists for this repo
in `ugiordan/architecture-analyzer` GitHub Actions artifacts.
Download it and pass via `--context` to enrich the adversarial
review with structured architecture data:

```bash
ARCH_CTX_DIR="${OUTPUT_DIR}/raw/arch-context"
ARTIFACT_NAME=$(gh api repos/ugiordan/architecture-analyzer/actions/artifacts \
  --jq ".artifacts[] | select(.name | endswith(\"${REPO_SHORT}\")) | .name" \
  2>/dev/null | head -1)
if [ -n "${ARTIFACT_NAME}" ]; then
  gh run download --repo ugiordan/architecture-analyzer \
    --name "${ARTIFACT_NAME}" --dir "${ARCH_CTX_DIR}" 2>/dev/null
  ARCH_DIR=$(dirname "$(find ${ARCH_CTX_DIR} -name component-architecture.json -type f 2>/dev/null | head -1)")
fi
```

Then invoke adversarial-reviewing with context if available:

```
Skill(skill="adversarial-reviewing:adversarial-reviewing", args="${REPO} --context architecture=${ARCH_DIR}")
```

Or without context if not available:

```
Skill(skill="adversarial-reviewing:adversarial-reviewing", args="${REPO}")
```

After it completes, invoke the semantic scanner:

```
Skill(skill="rhoai-security-scanner:audit", args="${REPO}")
```

Copy outputs to `${OUTPUT_DIR}/raw/semantic-scan/`.

Log each dispatch with `session_log.py agent`.

**Step 4: Collect results, normalize, deduplicate**

Wait for the background SAST scan to complete. Then:

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/normalize.py "${OUTPUT_DIR}/raw" > "${OUTPUT_DIR}/normalized-findings.json"
python3 ${CLAUDE_SKILL_DIR}/scripts/dedup.py "${OUTPUT_DIR}/normalized-findings.json" > "${OUTPUT_DIR}/deduplicated-findings.json"
```

**Step 4b: Triage**

Cross-correlate SAST and AI review findings. This merges all sources
into a single `triaged-findings.json` with confidence scores:

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/triage.py "${OUTPUT_DIR}" > "${OUTPUT_DIR}/triaged-findings.json"
```

The triage step:
- Corroborates findings detected by both SAST and AI review (highest confidence)
- Labels AI-only findings (code logic bugs SAST tools cannot detect)
- Demotes findings in non-production paths (scripts/templates/, examples/)
- Produces a unified, sorted finding list for reports

**Step 5: Generate reports**

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/report.py "${OUTPUT_DIR}" > "${OUTPUT_DIR}/executive-report.md"
python3 ${CLAUDE_SKILL_DIR}/scripts/report_mustfix.py "${OUTPUT_DIR}" > "${OUTPUT_DIR}/must-fix-report.md"
python3 ${CLAUDE_SKILL_DIR}/scripts/report_html.py "${OUTPUT_DIR}"  # MkDocs Material site -> security-report/
python3 ${CLAUDE_SKILL_DIR}/scripts/report_standalone.py "${OUTPUT_DIR}" > "${OUTPUT_DIR}/security-report.html"  # self-contained
python3 ${CLAUDE_SKILL_DIR}/scripts/report_docx.py "${OUTPUT_DIR}"
```

All reports. Every run. No exceptions.

**Step 6: Trends and session log**

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/trends.py --add "${OUTPUT_DIR}/scan-metadata.json" --trends-file "output/security-trends.json"
python3 ${CLAUDE_SKILL_DIR}/scripts/session_log.py finalize --session-file "${SESSION_FILE}"
```

Show the trends table and present the executive report to the user.

## Rules

Do not skip AI skills unless `--skip-ai` was explicitly passed.
Do not skip any of the three reports.
Do not add your own security analysis.
Do not modify the pipeline order.
If a step fails, log the error and continue to the next step.
