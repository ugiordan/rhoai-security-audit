# Security Audit Pipeline: Deterministic Orchestration and Sandboxing

**Date:** 2026-05-29
**Status:** In Progress
**Priority order:** Sandboxing > GitLab migration > Zero-day detection

## Problem

The security-audit skill is orchestrated by an LLM interpreting SKILL.md instructions. This has three documented failure modes:

1. **LLM improvisation:** The adversarial-reviewing skill was invoked but the hosting LLM dispatched 3 ad-hoc agents (security, architecture, infrastructure) that read SAST output instead of running the FSM orchestrator with 5 specialists reading source code. Three separate runs exhibited this behavior.

2. **Step skipping:** The SKILL.md includes a "CRITICAL: Verify adversarial-reviewing ran its FSM orchestrator" instruction. The LLM skipped it and reused cached output from a previous manual run.

3. **Report corruption:** `report_html.py` writes to a directory, not stdout, but the LLM added `> security-report.html` redirect because adjacent lines used redirects. The comment "NO redirect!" was added but the LLM can still ignore it.

None of these can be fixed by adding more instructions. The LLM is unreliable as an orchestrator for a deterministic pipeline.

## Design: Deterministic Pipeline Orchestrator

### Architecture

```
pipeline.py (Python, no LLM)
  |
  +-- Step 1: init session log
  +-- Step 2: scan_container.sh (SAST tools, local)
  +-- Step 3: for each AI skill:
  |     +-- spawn container (podman/docker)
  |     +-- inside container: claude -p "Skill(...)" 
  |     +-- verify output exists (code check, not LLM judgment)
  |     +-- collect outputs
  +-- Step 4: normalize.py + dedup.py + triage.py
  +-- Step 5: all report scripts (7 formats)
  +-- Step 6: trends.py + session_log.py
```

Each step is a Python function call. The LLM is only involved inside Step 3, where it runs the AI skill in an isolated Claude session that has no pipeline context and cannot skip steps or improvise alternatives.

### Key Design Decisions

**1. LLM is a worker, not an orchestrator.**
The pipeline script controls flow, error handling, retries, and output collection. Claude sessions are spawned as isolated subprocesses, one per AI skill, with no knowledge of the pipeline.

**2. Verification is code, not instructions.**
After each AI skill, `pipeline.py` checks for expected output files (e.g., `REPORT.md` in the FSM cache). If missing, the step fails. No "CRITICAL: verify" comments for the LLM to skip.

**3. SKILL.md is documentation, not execution.**
SKILL.md still exists for interactive use (`/security-audit` from Claude Code). CI and headless runs use `pipeline.py` directly.

**4. Timestamped output directories.**
Each run creates `output/<repo>/<YYYY-MM-DD-HHMMSS>/`. Multiple runs on the same day coexist. No overwrites.

### CLI

```bash
# Full pipeline
python3 pipeline.py opendatahub-io/kube-auth-proxy

# SAST only (no AI skills)
python3 pipeline.py opendatahub-io/kube-auth-proxy --skip-ai

# Regenerate reports from existing scan
python3 pipeline.py opendatahub-io/kube-auth-proxy --reports-only --scan-dir output/repo/2026-05-29-142244

# Disable sandboxing (local dev)
python3 pipeline.py opendatahub-io/kube-auth-proxy --no-sandbox
```

### Current Status

`pipeline.py` is implemented and tested. SAST-only pipeline runs in 34 seconds and generates all 7 report formats. AI skill invocation with container sandboxing is the next step.

## Design: Container-Based Sandboxing

### Why Containers, Not OpenShell

OpenShell (NVIDIA) provides fine-grained L7 network policies and per-sandbox filesystem isolation, but requires:
- Gateway daemon running on the host
- Platform-specific setup (Homebrew on macOS, systemd on Linux)
- Users to install it before running the skill

This violates the requirement that users should not install dependencies to run the skill. Podman/Docker is already present on most developer machines and CI runners.

### Sandbox Container Image

A pre-built container image (`quay.io/ugiordan/security-audit-ai:latest`) with:
- Claude Code CLI
- adversarial-reviewing plugin (pre-installed)
- rhoai-security-scanner plugin (pre-installed)
- Git (for repo cloning)
- Python 3 (for orchestrator scripts)
- No SAST tools (those run locally, outside the container)

```dockerfile
# Dockerfile.ai-sandbox
FROM registry.access.redhat.com/ubi9:latest

# System deps
RUN dnf install -y --nodocs git python3 python3-pip nodejs-npm && dnf clean all

# Claude Code CLI (npm package)
RUN npm install -g @anthropic-ai/claude-code

# Pre-install plugins at build time
# Plugin cache is baked into the image so no network fetch at runtime
RUN claude --version \
    && claude plugin install ugiordan/adversarial-reviewing \
    && claude plugin install ugiordan/rhoai-security-scanner

# Non-root user for sandboxing
RUN useradd -m scanner
USER scanner
WORKDIR /home/scanner

ENTRYPOINT ["claude"]
```

Note: The exact Claude Code install mechanism may change. If `claude` requires an API key at install time, we install just the CLI and plugins are fetched on first run (cached in the image layer via a build-time key that gets removed).


### Isolation Model

| Layer | Mechanism | What It Blocks |
|-------|-----------|----------------|
| Filesystem | Container boundary | No access to host filesystem beyond mounted volumes |
| Network | Custom podman network | Only `api.anthropic.com:443` allowed, all other egress blocked |
| Process | Container PID namespace | Cannot see or signal host processes |
| Credentials | Env var injection | Only `ANTHROPIC_API_KEY` passed, no access to host credentials |
| Resources | `--memory 4g --cpus 2` | Prevents resource exhaustion |

### Network Restriction

```bash
# Create a network that only allows Anthropic API
podman network create security-audit-ai \
  --dns 8.8.8.8 \
  --opt isolate=true

# Run with network restriction
podman run --rm \
  --network security-audit-ai \
  -e ANTHROPIC_API_KEY \
  -v /tmp/repo:/repo:ro \
  -v /tmp/output:/output \
  --memory 4g --cpus 2 \
  quay.io/ugiordan/security-audit-ai:latest \
  -p "Skill(skill='adversarial-reviewing:adversarial-reviewing', args='...')"
```

For full L7 enforcement (block everything except `POST api.anthropic.com/v1/messages`), we can add a squid/tinyproxy sidecar. This is a future enhancement, not needed for the initial version.

### Fallback Behavior

| Condition | Behavior |
|-----------|----------|
| podman/docker available | AI skills run in container with network restrictions |
| No container runtime + `--no-sandbox` | AI skills run locally, warning logged |
| No container runtime, no flag | AI skills run locally, warning logged |
| Container image not found | Pull image automatically, fail if pull fails |
| AI skill fails inside container | Retry once, then skip skill with warning |
| Container times out (1h) | Kill container, skip skill with warning |

## Design: GitLab Migration (Priority 2)

### Target

`gitlab.cee.redhat.com/rhoai-security/security-audit`

### Pipeline Trigger

Jira webhook fires when a ticket gets the `security-scan` label. GitLab CI receives the webhook, extracts the repo URL from the ticket, and runs `pipeline.py`.

### `.gitlab-ci.yml`

```yaml
stages:
  - scan

security-audit:
  stage: scan
  image: quay.io/ugiordan/security-audit-pipeline:latest
  variables:
    REPO: $JIRA_REPO_URL
  script:
    - python3 pipeline.py $REPO
  artifacts:
    paths:
      - output/*/
    expire_in: 30 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "trigger"
```

### Report Delivery

After the pipeline completes, a post-step attaches the reports to the Jira ticket using the Jira REST API. Reports are posted as restricted attachments, visible only to the `rhoai-prodsec` group.

### Container Images

Two images, built via the existing OpenShift BuildConfig:

1. **`security-audit-pipeline`**: Full pipeline image (SAST tools + Python + pipeline.py). Used as the GitLab CI job image.
2. **`security-audit-ai`**: AI sandbox image (Claude Code + plugins). Spawned by pipeline.py for AI skills.

### Migration Path

1. Push `pipeline.py` + Dockerfiles to `gitlab.cee.redhat.com/rhoai-security/security-audit`
2. Build images via OpenShift BuildConfig (already exists)
3. Configure GitLab CI with Jira webhook
4. Test with a single repo (kube-auth-proxy)
5. Remove the skill from `ugiordan/rhoai-security-audit` GitHub

## Design: Zero-Day / Embargo Detection (Priority 3)

### Phase 1: Enhanced AI Prompts + Public DB Cross-Reference

Update adversarial-reviewing agent profiles to explicitly look for patterns that match common zero-day categories:
- Authentication/authorization bypass without matching CVE
- RCE primitives (deserialization, template injection, command injection)
- SSRF chains that reach internal services
- Race conditions with security implications
- Cryptographic misuse (algorithm confusion, nonce reuse, timing attacks)

When the AI finds a suspicious pattern, the triage step cross-checks against public advisory databases (NVD, GHSA, OSV via their public APIs). If no public match exists, the finding is flagged as `POTENTIAL-ZERO-DAY` with a high confidence threshold.

### Phase 2: Threat Hunter Agent

A new specialist agent profile (`profiles/threat-hunter/`) in the adversarial-reviewing skill. Runs after the standard 5-specialist review, taking their findings as input. Its job:

1. Cross-reference each AI finding against public CVE databases
2. Check if the pattern matches known zero-day categories
3. Assess exploitability (is it reachable from an external attack surface?)
4. Flag anything with no public match and high exploitability as `POTENTIAL-ZERO-DAY`

### Phase 3: Red Hat Internal API Cross-Reference

When access is available, add cross-reference with Red Hat Product Security APIs (Hydra, Errata) to check if AI-discovered findings match embargoed issues. This requires internal API credentials and is deferred until access is granted.

### Report Integration

Findings flagged as `POTENTIAL-ZERO-DAY` get a distinct badge in all report formats (HTML, docx, MkDocs) and trigger a more prominent confidentiality warning. Reports containing potential zero-days should be delivered only via restricted Jira attachments, never posted in Slack channels.

## Implementation Order

1. **Done:** `pipeline.py` implemented and tested (SAST-only)
2. **Next:** Build `Dockerfile.ai-sandbox`, test full pipeline with container sandboxing
3. **Then:** Build `Dockerfile.pipeline` for GitLab CI
4. **Then:** Set up GitLab CI with Jira webhook trigger
5. **Then:** Add threat-hunter agent profile to adversarial-reviewing
6. **Then:** Add VEX integration (`/vex-check`, `/vex-scan` commands)

## Files

| File | Status | Description |
|------|--------|-------------|
| `scripts/pipeline.py` | Done | Deterministic orchestrator |
| `Dockerfile.ai-sandbox` | TODO | AI skill sandbox container |
| `Dockerfile.pipeline` | TODO | Full pipeline container for CI |
| `.gitlab-ci.yml` | TODO | GitLab CI pipeline config |
| `openshell-policy.yaml` | Deferred | OpenShell policy (for future CI use) |
| `profiles/threat-hunter/` | TODO | Zero-day detection agent profile |
