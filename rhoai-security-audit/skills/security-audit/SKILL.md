---
name: security-audit
description: Runs 15 SAST tools (in container) and AI security skills against repositories, normalizes outputs, deduplicates findings, generates consolidated markdown + HTML reports with trend tracking. Use when asked to scan repos, generate security reports, check vulnerabilities, review security posture, or track security trends.
---

# Security Audit

SAST + AI security analysis with consolidated reporting.

**USE FOR:** security scan, audit repo, check vulnerabilities, generate security report, show security trends, analyze security posture

**DO NOT USE FOR:** code review without security focus, dependency updates, general code quality

## Quick Start

```
/rhoai-security-audit:security-audit opendatahub-io/kube-auth-proxy
/rhoai-security-audit:security-audit report --full
/rhoai-security-audit:security-audit trends --last 10
```

## Workflow

Read [workflows/audit.md](workflows/audit.md) for the full pipeline:
1. SAST container + AI skills run **in parallel**
2. Normalize + deduplicate across all tools
3. Generate markdown + HTML reports
4. Update trend tracking
5. Write session transcript (model reasoning log)

For report-only or trends-only, see [workflows/report.md](workflows/report.md) and [workflows/trends.md](workflows/trends.md).

## Scripts

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/scan_container.sh <repo> <branch> <results-dir>
python3 ${CLAUDE_SKILL_DIR}/scripts/normalize.py <results-dir>
python3 ${CLAUDE_SKILL_DIR}/scripts/dedup.py <normalized.json>
python3 ${CLAUDE_SKILL_DIR}/scripts/report.py <output-dir> [--full]
python3 ${CLAUDE_SKILL_DIR}/scripts/report_html.py <output-dir> > report.html
python3 ${CLAUDE_SKILL_DIR}/scripts/trends.py --show --trends-file <file>
python3 ${CLAUDE_SKILL_DIR}/scripts/session_log.py init|step|agent|finalize
```

## Reference

- [Finding schema](reference/finding-schema.md)
- [Dedup rules](reference/dedup-rules.md)
- [AI skills config](ai-skills.yaml)
