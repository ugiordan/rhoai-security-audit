# Audit Workflow

Full security scan: SAST tools (in container) + AI skills + normalize + dedup + report.

## Checklist

```
Audit Progress:
- [ ] Step 1: Parse input and init session log
- [ ] Step 2: Run SAST tools in container
- [ ] Step 3: Run AI skills (adversarial-reviewing)
- [ ] Step 4: Normalize outputs
- [ ] Step 5: Deduplicate findings
- [ ] Step 6: Save metadata
- [ ] Step 7: Generate report
- [ ] Step 8: Update trends
- [ ] Step 9: Finalize session log
```

## Step 1: Parse input and init session log

Accept repos as:
- Space-separated args: `opendatahub-io/kserve opendatahub-io/odh-dashboard`
- Config file: `--config scan-config.yaml` (YAML with `repos:` list)

Parse flags. Set defaults for missing flags.

Create the output directory and initialize the session log:

```bash
DATE=$(date -u +%Y-%m-%d)
OUTPUT_DIR="output/${REPO_SHORT}/${DATE}"
mkdir -p "${OUTPUT_DIR}/raw"

python3 ${CLAUDE_SKILL_DIR}/scripts/session_log.py init \
  --repo "${REPO}" --output-dir "${OUTPUT_DIR}"
```

Save the `session_file` path from the JSON output. Log every step below.

To log a step:
```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/session_log.py step \
  --session-file "${SESSION_FILE}" \
  --name "Step name" --status ok \
  --detail "What happened" \
  --reasoning "Why this approach was chosen" \
  --duration <seconds>
```

## Step 2: Run SAST tools in container

All 15 SAST tools run inside a container. No tools need to be installed
on the host. The container clones the repo, runs all tools, and writes
results to a volume-mounted directory.

```bash
bash ${CLAUDE_SKILL_DIR}/scripts/scan_container.sh "${REPO}" "${BRANCH}" "${OUTPUT_DIR}/raw"
```

This script:
1. Detects docker or podman
2. Pulls `quay.io/ugiordan/security-audit-scanner:latest`
3. Runs all 15 tools inside the container
4. Writes results to `${OUTPUT_DIR}/raw/`
5. Falls back to running locally installed tools if no container runtime

After the scan, read `${OUTPUT_DIR}/raw/scan-summary.json` for tool
counts and timing. Log the step with this information.

Skip if `--skip-sast` flag is set. Log as skipped.

## Step 3: Run AI skills

AI skills are auto-installed as plugin dependencies. Invoke them
natively via the Skill tool.

### adversarial-reviewing

The adversarial-reviewing plugin is auto-installed as a dependency.
Invoke it against the repo:

```
Skill(skill="adversarial-reviewing:adversarial-reviewing", args="${REPO}")
```

After it completes, find the adversarial-reviewing cache directory
(printed during init) and copy its outputs:

```bash
mkdir -p "${OUTPUT_DIR}/raw/adversarial-reviewing"
cp -R /tmp/adversarial-review-cache-*/dispatch/*/output.md \
  "${OUTPUT_DIR}/raw/adversarial-reviewing/" 2>/dev/null || true
cp /tmp/adversarial-review-cache-*/outputs/* \
  "${OUTPUT_DIR}/raw/adversarial-reviewing/" 2>/dev/null || true
```

Log the agent dispatch:
```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/session_log.py agent \
  --session-file "${SESSION_FILE}" \
  --name "adversarial-reviewing" --phase "full-review" \
  --output-file "${OUTPUT_DIR}/raw/adversarial-reviewing/" \
  --model "<model-used>" --duration <seconds> \
  --findings-count <count>
```

### semantic-scan (rhoai-security-scanner)

The rhoai-security-scanner plugin (Matthew's semantic scanner) is
auto-installed as a dependency. It uses 3 agents: repo-analyst,
security-scanner, post-scan-agent.

Invoke it against the repo:

```
Skill(skill="rhoai-security-scanner:audit", args="${REPO}")
```

After it completes, copy its outputs:

```bash
mkdir -p "${OUTPUT_DIR}/raw/semantic-scan"
# Copy any output files the scanner produced
find /tmp -maxdepth 3 -name "*.json" -path "*rhoai-security-scanner*" \
  -exec cp {} "${OUTPUT_DIR}/raw/semantic-scan/" \; 2>/dev/null || true
```

Log the agent dispatch:
```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/session_log.py agent \
  --session-file "${SESSION_FILE}" \
  --name "semantic-scan" --phase "full-scan" \
  --output-file "${OUTPUT_DIR}/raw/semantic-scan/" \
  --model "<model-used>" --duration <seconds> \
  --findings-count <count>
```

**Important**: Log every agent dispatch, including the model used,
duration, and reasoning. This creates a full audit trail.

Skip if `--skip-ai` flag is set. Log as skipped.

## Step 4: Normalize outputs

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/normalize.py" "${OUTPUT_DIR}/raw" \
  > "${OUTPUT_DIR}/normalized-findings.json"
```

Log the step with finding counts per tool.

## Step 5: Deduplicate findings

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/dedup.py" \
  "${OUTPUT_DIR}/normalized-findings.json" \
  > "${OUTPUT_DIR}/deduplicated-findings.json"
```

Log with raw vs deduped counts.

## Step 6: Save metadata

Create scan-metadata.json with all run details:
- date, repo, branch, commit SHA
- tools_run (from scan-summary.json)
- ai_skills_run
- finding counts by severity (from deduplicated findings)

## Step 7: Generate report

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/report.py" "${OUTPUT_DIR}" \
  > "${OUTPUT_DIR}/executive-report.md"
```

If `--ai-prioritize` flag is set, review the critical/high findings
and rank by actual exploitability before generating the report.
Log your reasoning for each prioritization decision.

Present the executive report to the user.

## Step 8: Update trends

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/trends.py" \
  --add "${OUTPUT_DIR}/scan-metadata.json" \
  --trends-file "output/security-trends.json"
```

Show the trends table to the user.

## Step 9: Finalize session log

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/session_log.py finalize \
  --session-file "${SESSION_FILE}"
```

This writes `session-log.json` (structured) and
`session-transcript.md` (human-readable) to the output directory.
The transcript includes all step timings, reasoning, and AI agent
dispatch details with prompt/output previews.
