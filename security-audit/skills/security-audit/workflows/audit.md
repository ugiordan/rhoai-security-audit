# Audit Workflow

Full security scan: SAST tools (in container) + AI skills, run in parallel.

## Checklist

```
Audit Progress:
- [ ] Step 1: Parse input and init session log
- [ ] Step 2: Run SAST + AI skills IN PARALLEL
      - [ ] 2a: SAST tools in container (background)
      - [ ] 2b: adversarial-reviewing
      - [ ] 2c: semantic-scan (security-scanner)
- [ ] Step 3: Collect parallel results
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

## Step 2: Run SAST + AI skills IN PARALLEL

SAST tools and AI skills are independent. Run them at the same time.

### 2a: Start SAST container in background

Launch the SAST container scan as a background task. It clones the repo
internally, runs all 15 tools, writes results to `${OUTPUT_DIR}/raw/`.

```bash
bash ${CLAUDE_SKILL_DIR}/scripts/scan_container.sh "${REPO}" "${BRANCH}" "${OUTPUT_DIR}/raw" &
```

Or use the Bash tool with `run_in_background: true`:
```
Bash(command="bash ${CLAUDE_SKILL_DIR}/scripts/scan_container.sh '${REPO}' '${BRANCH}' '${OUTPUT_DIR}/raw'", run_in_background=true)
```

The container:
1. Detects docker or podman
2. Pulls `quay.io/ugiordan/security-audit-scanner:latest`
3. Runs all 15 tools inside the container
4. Writes results to `${OUTPUT_DIR}/raw/`
5. Falls back to running locally installed tools if no container runtime

Skip if `--skip-sast` flag is set. Log as skipped.

### 2b: Run AI skills while SAST runs

While the SAST container runs in the background, invoke AI skills.
The list of AI skills is defined in `ai-skills.yaml` (in the skill
directory). Adding a new AI skill is just adding an entry to that file
and listing it in plugin.json dependencies.

Read the skills config:
```bash
cat ${CLAUDE_SKILL_DIR}/ai-skills.yaml
```

For each skill entry in `skills:`, invoke it:

```
Skill(skill="<entry.skill>", args="${REPO}")
```

After each skill completes, copy its outputs:
```bash
mkdir -p "${OUTPUT_DIR}/raw/<entry.name>"
cp -R <entry.output_pattern> "${OUTPUT_DIR}/raw/<entry.name>/" 2>/dev/null || true
```

Log each agent dispatch:
```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/session_log.py agent \
  --session-file "${SESSION_FILE}" \
  --name "<entry.name>" --phase "full-review" \
  --output-file "${OUTPUT_DIR}/raw/<entry.name>/" \
  --model "<model-used>" --duration <seconds> \
  --findings-count <count>
```

Skip AI skills if `--skip-ai` flag is set. Log as skipped.

## Step 3: Collect parallel results

Wait for the background SAST container to complete. Read
`${OUTPUT_DIR}/raw/scan-summary.json` for tool counts and timing.

Log the SAST step with tool count, findings count, and duration.

**Important**: Log every agent dispatch, including the model used,
duration, and reasoning. This creates a full audit trail.

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

## Step 7: Generate reports

Generate all three report formats:

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/report.py" "${OUTPUT_DIR}" \
  > "${OUTPUT_DIR}/executive-report.md"

python3 "${CLAUDE_SKILL_DIR}/scripts/report_mustfix.py" "${OUTPUT_DIR}" \
  > "${OUTPUT_DIR}/must-fix-report.md"

python3 "${CLAUDE_SKILL_DIR}/scripts/report_html.py" "${OUTPUT_DIR}" \
  > "${OUTPUT_DIR}/security-report.html"
```

If `--ai-prioritize` flag is set, review the critical/high findings
and rank by actual exploitability before generating the report.
Log your reasoning for each prioritization decision.

Present the executive report to the user and mention the HTML report
is available for browser viewing.

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
