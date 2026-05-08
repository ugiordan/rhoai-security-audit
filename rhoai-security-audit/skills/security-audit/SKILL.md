---
name: security-audit
description: >
  Runs SAST tools and AI security skills against repositories, normalizes
  outputs, deduplicates findings, and generates consolidated reports with
  trend tracking. Use when asked to scan repos, generate security reports,
  check vulnerabilities, review security posture, or track security trends.
---

# Security Audit

Full security analysis: SAST tools + AI skills, normalized output,
deduplicated findings, consolidated reports, trend tracking.

## Quick Start

```bash
# Scan a single repo (SAST + AI + report + trends)
/security-audit opendatahub-io/opendatahub-operator

# Scan multiple repos
/security-audit opendatahub-io/kserve opendatahub-io/odh-dashboard

# Scan repos from config file
/security-audit --config scan-config.yaml

# Generate report from existing scan data
/security-audit:report --full

# View trends across runs
/security-audit:trends --last 10
```

## Commands

### `/security-audit <repos> [flags]`

Full scan: SAST tools + AI skills + normalize + dedup + report + trends.
See [commands/audit.md](commands/audit.md) for detailed steps.

### `/security-audit:report [flags]`

Generate reports from existing scan data (no new scan).
See [commands/report.md](commands/report.md) for details.

### `/security-audit:trends [flags]`

Show trends across previous runs.
See [commands/trends.md](commands/trends.md) for details.

## Flags

| Flag | Command | Default | Description |
|------|---------|---------|-------------|
| `--config <file>` | audit | - | YAML file with repos list |
| `--branch <name>` | audit | main | Branch to scan |
| `--output <dir>` | all | ./output | Output directory |
| `--skip-sast` | audit | false | Skip SAST tools |
| `--skip-ai` | audit | false | Skip AI skills |
| `--ai-prioritize` | audit | false | AI-assisted finding ranking |
| `--parallel <n>` | audit | 2 | Max concurrent repo scans |
| `--full` | report | false | Include all severities |
| `--format <md\|docx>` | report | md | Report format |
| `--date <YYYY-MM-DD>` | report | latest | Use specific scan date |
| `--repo <name>` | report, trends | all | Filter to specific repo |
| `--last <n>` | trends | 10 | Show last N entries |

## Command Routing

When the user's request does not explicitly name a command, determine
intent from context:

- "scan", "audit", "analyze", "check security" -> `/security-audit`
- "report", "summary", "findings" (no scan requested) -> `/security-audit:report`
- "trends", "history", "over time", "track" -> `/security-audit:trends`
- Ambiguous or "do everything" -> chain: audit -> report -> trends

## Output Structure

```
output/
  <repo-name>/
    <YYYY-MM-DD>/           # Each run gets a dated directory
      raw/                  # Raw tool outputs (JSON/SARIF per tool)
      normalized-findings.json
      deduplicated-findings.json
      scan-metadata.json
      executive-report.md
    <YYYY-MM-DD>-2/         # Counter appended if date dir exists
  security-trends.json      # Accumulated across all runs
```

## Tools

**SAST** (via scan-repo.sh): semgrep, gitleaks, trufflehog, kube-linter,
hadolint, actionlint, zizmor, shellcheck, trivy, grype, govulncheck,
pip-audit, osv-scanner, gosec, yamllint

**AI Skills** (native invocation): adversarial-reviewing, semantic-scan
(rhoai-security-scanner:audit)

## Normalization

All tool outputs are normalized to a common format.
See [reference/finding-schema.md](reference/finding-schema.md).

## Deduplication

Findings from multiple tools pointing to the same issue are merged.
See [reference/dedup-rules.md](reference/dedup-rules.md).
