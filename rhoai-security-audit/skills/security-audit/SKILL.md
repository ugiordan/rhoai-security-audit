---
name: security-audit
description: Runs 15 SAST tools and AI security skills against repositories, normalizes outputs, deduplicates findings, generates consolidated markdown + HTML reports with trend tracking. Use when asked to scan repos, generate security reports, check vulnerabilities, review security posture, or track security trends.
---

# Security Audit

**USE FOR:** security scan, audit repo, check vulnerabilities, generate security report, show security trends

**DO NOT USE FOR:** code review without security focus, dependency updates, general code quality

## Steps (MUST follow in order)

### 1. SAST scan (background)

```bash
bash ${CLAUDE_SKILL_DIR}/scripts/scan_container.sh "${REPO}" "${BRANCH}" "${OUTPUT_DIR}/raw"
```

Run in background. This installs tools to `~/.cache/security-audit-tools/` on first run, then scans with all 15 SAST tools.

### 2. AI skills (while SAST runs)

Read [ai-skills.yaml](ai-skills.yaml) for the list. Invoke EACH skill:

```
Skill(skill="adversarial-reviewing:adversarial-reviewing", args="${REPO}")
Skill(skill="rhoai-security-scanner:audit", args="${REPO}")
```

Skip only if `--skip-ai` flag is passed. Log each dispatch.

### 3. Normalize + deduplicate

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/normalize.py "${OUTPUT_DIR}/raw" > "${OUTPUT_DIR}/normalized-findings.json"
python3 ${CLAUDE_SKILL_DIR}/scripts/dedup.py "${OUTPUT_DIR}/normalized-findings.json" > "${OUTPUT_DIR}/deduplicated-findings.json"
```

### 4. Generate ALL THREE reports

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/report.py "${OUTPUT_DIR}" > "${OUTPUT_DIR}/executive-report.md"
python3 ${CLAUDE_SKILL_DIR}/scripts/report_mustfix.py "${OUTPUT_DIR}" > "${OUTPUT_DIR}/must-fix-report.md"
python3 ${CLAUDE_SKILL_DIR}/scripts/report_html.py "${OUTPUT_DIR}" > "${OUTPUT_DIR}/security-report.html"
```

### 5. Trends + session log

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/trends.py --add "${OUTPUT_DIR}/scan-metadata.json" --trends-file "output/security-trends.json"
python3 ${CLAUDE_SKILL_DIR}/scripts/session_log.py finalize --session-file "${SESSION_FILE}"
```

## Reference

- [Full workflow details](workflows/audit.md)
- [Finding schema](reference/finding-schema.md)
- [Dedup rules](reference/dedup-rules.md)
- [AI skills config](ai-skills.yaml)
