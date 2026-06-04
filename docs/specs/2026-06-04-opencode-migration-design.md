# LLM-Agnostic Skill Framework: OpenCode Migration

**Date:** 2026-06-04
**Status:** Design (v2, post-adversarial review)
**Branch:** `feat/opencode-migration`

## Problem

The security-audit and adversarial-reviewing skills are locked to Claude Code's
proprietary skill system. Users cannot swap LLM providers without rewriting the
entire skill infrastructure. The skill format (SKILL.md with YAML frontmatter)
is identical between Claude Code and OpenCode, but the orchestration layer
(subprocess calls, plugin discovery, permissions) differs.

## Goals

1. Skills work in both Claude Code and OpenCode without modification
2. Users can swap LLM providers (Claude, GPT, Gemini, local models) via config
3. `pipeline.py` detects the active harness at runtime and adapts
4. No hook dependencies (already eliminated)
5. Backward compatible: existing Claude Code users aren't broken

## Non-Goals

- Rewriting skills in a new format
- Dropping Claude Code support
- Building a custom harness

## Design

### Harness Detection

`pipeline.py` detects the active harness at startup. Priority order ensures
backward compatibility (Claude Code preferred when both are installed) and
fails clearly when nothing is available:

```python
def detect_harness():
    # 1. Explicit env var (highest priority, not spoofable via repo files)
    harness_override = os.environ.get("SECURITY_AUDIT_HARNESS", "").lower()
    if harness_override in ("claude", "opencode"):
        return harness_override

    # 2. Claude Code env var (set by Claude Code itself, not user-configurable)
    if os.environ.get("CLAUDE_SKILL_DIR"):
        return "claude"

    # 3. Claude Code binary (backward compat: prefer claude when both installed)
    if shutil.which("claude"):
        return "claude"

    # 4. OpenCode binary
    if shutil.which("opencode"):
        return "opencode"

    # 5. No harness found: fail loudly
    log("No AI harness found. Install Claude Code or OpenCode.", level="ERROR")
    sys.exit(1)
```

The `SECURITY_AUDIT_HARNESS` env var lets users explicitly choose, overriding
auto-detection. This is the only env var used for harness selection: it's set
by the user in their shell profile or CI config, not by repo files.

### AI Skill Invocation

The subprocess call adapts based on harness:

```python
if harness == "claude":
    cmd = [
        "claude", "--add-dir", str(plugin_dir),
        "-p", prompt,
        "--allowedTools", "Bash,Read,Write,Grep,Glob,Skill,Agent",
        "--max-turns", "100",
    ]
elif harness == "opencode":
    cmd = ["opencode", "run"]
    if model:
        cmd.extend(["--model", model])
    cmd.extend([
        "--permission", json.dumps({
            "bash": "allow", "read": "allow", "edit": "allow",
            "glob": "allow", "grep": "allow", "skill": "allow",
            "task": "allow",
        }),
        prompt,
    ])
```

Key differences:
- Claude Code: `claude -p "prompt"` with `--allowedTools` whitelist
- OpenCode: `opencode run "prompt"` with `--permission` JSON for tool allowlist
  (NOT `--dangerously-skip-permissions`, which disables all checks)
- Model is only passed when explicitly set (avoids `--model None`)

### Sandboxing

OpenShell sandboxing applies to both harnesses. The sandbox wraps the entire
subprocess call regardless of whether it's `claude` or `opencode`:

```python
if sandbox and _ensure_openshell():
    return _run_in_openshell(cmd, name)
else:
    return _run_locally(cmd)
```

The OpenShell policy restricts network egress to `api.anthropic.com:443` (or
the configured provider endpoint). For non-Anthropic providers, the policy
must be updated to allow the provider's API endpoint. `pipeline.py` generates
the policy dynamically based on the configured model's provider:

```python
PROVIDER_ENDPOINTS = {
    "anthropic": "api.anthropic.com",
    "openai": "api.openai.com",
    "google": "generativelanguage.googleapis.com",
    "azure": "REQUIRES_EXPLICIT_CONFIG",  # user must set SECURITY_AUDIT_PROVIDER_HOST
}
```

Unknown providers (e.g., `ollama/llama3` for local models) default to blocking
all egress. The user must add the endpoint explicitly via
`SECURITY_AUDIT_PROVIDER_HOST` env var or the pipeline fails with a clear error
listing the known providers. This prevents fail-open on unknown providers.

When no container runtime is available AND `--no-sandbox` is NOT set,
the pipeline fails with an error (fail-closed, not silent fallback):

```python
if sandbox and not _ensure_openshell():
    if not detect_container_runtime():
        log("No sandbox available (no OpenShell, no container runtime). "
            "Use --no-sandbox to run without isolation.", level="ERROR")
        sys.exit(1)
```

### Directory Structure

```
rhoai-security-audit/
  skills/
    security-audit/
      SKILL.md                  # works in both harnesses
      scripts/
        pipeline.py             # harness-agnostic orchestrator
        normalize.py
        dedup.py
        triage.py
        report_common.py
        report_standalone.py
        report_mustfix.py
        report_html.py
        report_docx.py
        report.py
        openshell-policy.yaml
        scan_container.sh
        install_tools.sh
        run_all.sh
        session_log.py
        trends.py
        tests/
          test_dedup.py
          test_triage.py
    adversarial-reviewing/      # symlink or copy from adversarial-reviewing repo
  opencode.json                 # OpenCode provider config
  .claude-plugin/               # Claude Code plugin manifest (backward compat)
    plugin.json
    marketplace.json
```

Both harnesses discover skills from the `skills/` directory. Claude Code uses
`--add-dir`, OpenCode uses config path in `opencode.json`.

### SKILL.md Format

The SKILL.md delegates to pipeline.py. Both harnesses resolve the skill
directory differently, so we use a portable invocation:

```yaml
---
name: security-audit
description: Runs SAST tools and AI skills, generates security reports.
---

# Security Audit

python3 ${CLAUDE_SKILL_DIR:-.}/scripts/pipeline.py $ARGUMENTS
```

The `${CLAUDE_SKILL_DIR:-.}` syntax falls back to `.` (current directory) when
the variable isn't set (OpenCode case). Since `pipeline.py` resolves its own
location via `Path(__file__).resolve().parent.parent`, the actual skill
directory is always correct regardless of invocation path.

Note: `$ARGUMENTS` is expanded by the hosting LLM, not by a shell. The LLM
constructs the command from user input which has already been parsed by
`pipeline.py`'s argparse. Injection via `$ARGUMENTS` requires the LLM itself
to inject malicious flags, which is a prompt injection risk mitigated by the
sandbox (network-restricted, no host filesystem access beyond the repo).

### Model Configuration

OpenCode config (`opencode.json`):

```json
{
  "model": "anthropic/claude-sonnet-4-6",
  "small_model": "anthropic/claude-haiku-4-5",
  "provider": {
    "anthropic": {}
  }
}
```

Users swap providers by changing `model`:
- `"openai/gpt-4o"` for GPT
- `"google/gemini-2.5-pro"` for Gemini
- `"ollama/llama3"` for local models

`pipeline.py` reads the model from:
1. `--model` CLI flag (highest priority)
2. `SECURITY_AUDIT_MODEL` env var
3. Harness default (whatever the user configured in their profile)

When no model is specified, the `--model` flag is omitted entirely (not
passed as `--model None`).

### Permissions

Claude Code: `--allowedTools "Bash,Read,Write,Grep,Glob,Skill,Agent"`

OpenCode: `--permission '{"bash":"allow","read":"allow",...}'` (inline JSON)

Both are explicit tool allowlists. Neither uses blanket permission bypasses.
The `--dangerously-skip-permissions` flag is NOT used because it disables all
permission checks, granting unrestricted tool access. Instead, we pass the
specific permission set needed.

### GitLab CI Integration

The Jira webhook input must be validated before use:

```yaml
security-audit:
  stage: scan
  variables:
    REPO: $JIRA_REPO_URL
  script:
    - |
      if ! echo "$REPO" | grep -qE '^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$'; then
        echo "ERROR: Invalid repo format: $REPO" >&2
        exit 1
      fi
    - python3 pipeline.py "$REPO"
```

The `$REPO` variable is always quoted in shell context to prevent injection.
`pipeline.py` also validates repo format internally as a defense-in-depth
measure.

**Jira webhook authentication:** The webhook endpoint must verify the request
originates from Jira using a shared secret or HMAC signature. Without this,
anyone who knows the trigger URL can submit forged scan requests with arbitrary
repo values.

**GitLab CI trigger scope:** The pipeline rule `$CI_PIPELINE_SOURCE == "trigger"`
accepts any valid trigger token. Restrict to specific token holders or add a
second condition validating the source (e.g., Jira IP allowlist). Consider using
GitLab's webhook secret validation instead of open trigger tokens.

These are GitLab infrastructure concerns, not pipeline.py concerns, but must be
configured correctly when deploying the CI integration
measure.

### Adversarial-Reviewing Integration

The adversarial-reviewing skill uses Agent/Task tool for subagent dispatch.
Both harnesses support this:

- Claude Code: `Agent(subagent_type="review-specialist", prompt="...")`
- OpenCode: Task tool dispatches subagents based on agent definitions

The FSM orchestrator (`scripts/orchestrator/`) is pure Python and doesn't
depend on the harness. It writes dispatch.json, the hosting session reads it
and dispatches agents via whichever tool is available.

### Testing Strategy

1. **Unit tests**: existing test_dedup.py and test_triage.py (harness-independent)
2. **Harness detection tests**: verify priority order, env var override, fail-closed
3. **E2E test with Claude Code**: full pipeline, verify reports
4. **E2E test with OpenCode**: full pipeline with Claude model, verify reports
5. **Comparison test**: run both on same repo, verify same SAST findings
6. **Provider swap test**: run with OpenCode + different model, verify completion
7. **Sandbox test**: verify OpenShell policy blocks non-provider endpoints

### Migration Steps

1. Create `feat/opencode-migration` branch
2. Add `detect_harness()` with correct priority order to pipeline.py
3. Add OpenCode subprocess path with `--permission` (not `--dangerously-skip-permissions`)
4. Add dynamic OpenShell policy based on provider
5. Make sandbox fail-closed (no silent fallback)
6. Add `--model` flag with None guard
7. Create `opencode.json` with provider config
8. Test with Claude Code (regression)
9. Install OpenCode, test with OpenCode + Claude model
10. Test with OpenCode + different model
11. Verify sandbox blocks non-provider endpoints
12. Update SKILL.md with portable invocation
13. Merge after all tests pass

### Risk Assessment

| Risk | Mitigation |
|------|-----------|
| OpenCode skill discovery differs | SKILL.md format is identical, only paths differ |
| Agent dispatch works differently | FSM orchestrator is Python, not harness-dependent |
| Provider-specific prompt differences | pipeline.py prompt is model-agnostic |
| OpenCode headless mode less mature | Fallback to Claude Code (preferred in detection) |
| Breaking existing Claude Code users | Dual support, Claude preferred in auto-detection |
| Harness detection spoofing | Only `SECURITY_AUDIT_HARNESS` env var honored, not repo files |
| Silent sandbox bypass | Fail-closed when no sandbox available without `--no-sandbox` |
| Unrestricted permissions | Explicit allowlist, never `--dangerously-skip-permissions` |
| OpenCode path skips sandboxing | Same OpenShell sandbox wraps both harness subprocess calls |
| Unknown provider blocks egress | Fail-closed: unknown providers require explicit endpoint config |
| Jira webhook forgery | Webhook must use shared secret/HMAC validation (infra concern) |
| GitLab CI open trigger | Restrict trigger tokens, add IP allowlist (infra concern) |
| $ARGUMENTS injection via LLM | Mitigated by sandbox (no host access) + argparse validation |
| Azure endpoint wildcard | Azure requires explicit host config (no wildcard allowed) |

## Success Criteria

1. `/security-audit repo` works from both Claude Code and OpenCode sessions
2. `pipeline.py repo` works as a standalone script regardless of harness
3. User can swap model by changing one config line
4. All existing unit tests pass
5. E2E pipeline produces valid reports with both harnesses
6. Sandbox is enforced by default (fail-closed without `--no-sandbox`)
7. No `--dangerously-skip-permissions` in any code path
