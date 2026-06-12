---
name: security-audit
description: Runs SAST tools and AI skills, generates security reports. Works with Claude Code and OpenCode.
---

# Security Audit

This skill delegates to `pipeline.py`, a deterministic Python
orchestrator. Do not orchestrate steps yourself.

## How to run

Run the pipeline in the background, then poll the output for progress:

```bash
python3 ${CLAUDE_SKILL_DIR:-.}/scripts/pipeline.py $ARGUMENTS
```

Use `run_in_background: true` for the Bash tool, then poll the output
file every 60 seconds using `tail -5 <output_file>` to relay progress
to the user. Key lines to watch for:

- `Step 2: SAST scan complete` (SAST done, usually ~30s)
- `Invoking adversarial-reviewing...` (AI review started)
- `adversarial-reviewing complete` (AI review done, usually 15-30min)
- `semantic-scan complete` (semantic scan done, usually 5-10min)
- `Pipeline complete` (all done, present results)

When the pipeline completes, present the results summary and report
file locations to the user.

## Flags

| Flag | Effect |
|------|--------|
| `--skip-ai` | Skip AI skills, SAST only |
| `--no-cache` | Clear AI skill caches, force fresh review |
| `--no-sandbox` | Run AI skills without container isolation |
| `--reports-only` | Regenerate reports from existing scan data |
| `--scan-dir <path>` | Specify scan directory for `--reports-only` |
| `--branch <name>` | Branch to scan (default: main) |
| `--arch-context <path>` | Path or GitHub repo for architecture context |
| `--model <model>` | LLM model (e.g. openai/gpt-4o). Default: harness config |

## Rules

Do not orchestrate steps yourself. Do not add your own security
analysis. Do not invoke AI skills directly. Let pipeline.py handle
everything. If it fails, report the error to the user.
