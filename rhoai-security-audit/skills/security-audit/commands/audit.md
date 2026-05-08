# Audit Command

Full security scan: SAST tools + AI skills + normalize + dedup + report.

## Checklist

```
Audit Progress:
- [ ] Step 1: Parse input (repos, flags)
- [ ] Step 2: Clone repos
- [ ] Step 3: Run SAST tools
- [ ] Step 4: Run AI skills
- [ ] Step 5: Normalize outputs
- [ ] Step 6: Deduplicate findings
- [ ] Step 7: Save results
- [ ] Step 8: Generate report
- [ ] Step 9: Update trends
```

## Step 1: Parse input

Accept repos as:
- Space-separated args: `opendatahub-io/kserve opendatahub-io/odh-dashboard`
- Config file: `--config scan-config.yaml` (YAML with `repos:` list)

Parse flags. Set defaults for missing flags.

## Step 2: Clone repos

For each repo:
```bash
WORKDIR=$(mktemp -d)
git clone --depth 1 --branch "${BRANCH:-main}" \
  "https://github.com/${REPO}.git" "$WORKDIR/repo"
```

## Step 3: Run SAST tools

Find `scan-repo.sh` in the scanner installation:
```bash
SCANNER_DIR="$(cd "$(dirname "${SKILL_DIR}")/../.." && pwd)"
bash "${SCANNER_DIR}/scripts/scan-repo.sh" "$WORKDIR/repo" "$RESULTS_DIR"
```

If `scan-repo.sh` is not found, run tools individually.
See [../reference/tool-normalization.md](../reference/tool-normalization.md).

Skip if `--skip-sast` flag is set.

## Step 4: Run AI skills

Run native AI skills against the cloned repo:

1. **adversarial-reviewing**: Invoke `/adversarial-reviewing` with the
   repo path. This runs the FSM orchestrator with 5 specialist agents.
2. **semantic-scan**: Invoke `/rhoai-security-scanner:audit` with the
   repo path. This runs Matthew's 3-agent security analysis.

Save AI skill outputs alongside SAST results in the raw/ directory.

Skip if `--skip-ai` flag is set.

## Step 5: Normalize outputs

```bash
python3 "${SKILL_DIR}/scripts/normalize.py" "$RESULTS_DIR" \
  > "$OUTPUT_DIR/normalized-findings.json"
```

This converts all tool outputs to the common finding format.

## Step 6: Deduplicate findings

```bash
python3 "${SKILL_DIR}/scripts/dedup.py" \
  "$OUTPUT_DIR/normalized-findings.json" \
  > "$OUTPUT_DIR/deduplicated-findings.json"
```

## Step 7: Save results

Create output directory: `output/<repo-name>/<YYYY-MM-DD>/`

If the dated directory already exists, append a counter (`-2`, `-3`, etc.).

Save:
- `raw/` directory with all tool outputs
- `normalized-findings.json`
- `deduplicated-findings.json`
- `scan-metadata.json` with: date, repo, branch, commit SHA, tools run,
  duration, finding counts by severity

## Step 8: Generate report

```bash
python3 "${SKILL_DIR}/scripts/report.py" "$OUTPUT_DIR" \
  > "$OUTPUT_DIR/executive-report.md"
```

If `--ai-prioritize` flag is set, review the critical/high findings
and rank them by actual exploitability before generating the report.

Present the executive report to the user.

## Step 9: Update trends

```bash
python3 "${SKILL_DIR}/scripts/trends.py" \
  --add "$OUTPUT_DIR/scan-metadata.json" \
  --trends-file "output/security-trends.json"
```

## Cleanup

```bash
rm -rf "$WORKDIR"
```
