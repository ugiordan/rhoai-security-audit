#!/usr/bin/env python3
"""Deterministic security audit pipeline.

Removes the LLM from the orchestration loop. Each step is a Python function
that shells out to tools or spawns isolated Claude sessions for AI skills.
AI skills run inside a container with restricted networking.

Usage:
    python3 pipeline.py opendatahub-io/kube-auth-proxy
    python3 pipeline.py opendatahub-io/kube-auth-proxy --skip-ai
    python3 pipeline.py opendatahub-io/kube-auth-proxy --reports-only --scan-dir output/repo/2026-05-29-142244
    python3 pipeline.py opendatahub-io/kube-auth-proxy --no-sandbox
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


SKILL_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = SKILL_DIR / "scripts"

CONTAINER_RUNTIME = None
AI_SANDBOX_IMAGE = os.environ.get(
    "SECURITY_AUDIT_AI_IMAGE",
    "quay.io/ugiordan/security-audit-ai:v1.0.0",
)

AI_SKILLS = [
    {
        "name": "adversarial-reviewing",
        "skill": "adversarial-reviewing:adversarial-reviewing",
        "verify_glob": "**/outputs/REPORT.md",
        "output_dir": "adversarial-reviewing",
    },
    {
        "name": "semantic-scan",
        "skill": "rhoai-security-scanner:audit",
        "verify_glob": "**/*security-report*.md",
        "output_dir": "semantic-scan",
    },
]


def log(msg, level="INFO"):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)


def run(cmd, check=True, capture=False, timeout=None, shell=False):
    """Run a command. Prefer list form to avoid shell injection."""
    result = subprocess.run(
        cmd, shell=shell, capture_output=capture,
        text=True, timeout=timeout,
    )
    if check and result.returncode != 0:
        stderr = result.stderr[:500] if result.stderr else ""
        raise RuntimeError(f"Command failed (exit {result.returncode}): {cmd}\n{stderr}")
    return result


def detect_container_runtime():
    """Find podman or docker."""
    for rt in ["podman", "docker"]:
        if shutil.which(rt):
            return rt
    return None


def step_init(repo, output_dir):
    """Step 1: Initialize session log and output directory."""
    log(f"Step 1: Init ({repo} -> {output_dir})")
    os.makedirs(f"{output_dir}/raw", mode=0o700, exist_ok=True)
    result = run(
        ["python3", str(SCRIPTS_DIR / "session_log.py"), "init",
         "--repo", repo, "--output-dir", output_dir],
        capture=True,
    )
    data = json.loads(result.stdout)
    return data["session_file"]


def step_sast_scan(repo, output_dir, branch="main"):
    """Step 2: Run SAST scan (foreground, blocking)."""
    log("Step 2: SAST scan")
    scan_script = str(SCRIPTS_DIR / "scan_container.sh")
    run(["bash", scan_script, repo, branch, f"{output_dir}/raw"], timeout=600)
    log("Step 2: SAST scan complete")


def _clear_ai_caches():
    """Remove adversarial-review and security-scan caches to force fresh runs."""
    import glob as _glob
    patterns = [
        "/tmp/adversarial-review-cache-*",
        str(Path.home() / ".claude/plugins/cache/*/adversarial-reviewing/*/skills/adversarial-reviewing/.adversarial-review-cache/*"),
        ".security-scan/security-scan-*",
    ]
    removed = 0
    for pat in patterns:
        for d in _glob.glob(pat):
            if Path(d).is_dir():
                shutil.rmtree(d, ignore_errors=True)
                removed += 1
    return removed


def step_ai_skills(repo, output_dir, session_file, sandbox=True, no_cache=False):
    """Step 3: Invoke AI skills in isolated containers."""
    log("Step 3: AI skills")
    if no_cache:
        removed = _clear_ai_caches()
        log(f"  Cleared {removed} AI skill caches (--no-cache)")
    runtime = detect_container_runtime() if sandbox else None

    for skill_cfg in AI_SKILLS:
        name = skill_cfg["name"]
        skill_id = skill_cfg["skill"]
        out_subdir = skill_cfg["output_dir"]

        log(f"  Invoking {name}...")
        run(
            ["python3", str(SCRIPTS_DIR / "session_log.py"), "agent",
             "--session-file", session_file, "--name", name, "--phase", "started"],
            check=False,
        )

        start = time.time()
        success = _invoke_ai_skill(repo, skill_id, name, runtime, sandbox)
        duration = time.time() - start

        if success:
            _collect_ai_output(name, skill_cfg, output_dir)
            log(f"  {name} complete ({duration:.0f}s)")
        else:
            log(f"  {name} FAILED ({duration:.0f}s)", level="WARN")

        run(
            ["python3", str(SCRIPTS_DIR / "session_log.py"), "agent",
             "--session-file", session_file, "--name", name, "--phase", "completed"],
            check=False,
        )


def _setup_scanner_workspace(repo):
    """Create workspace for rhoai-security-scanner since its hooks don't fire in pipeline mode."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%S")
    workspace = Path(f".security-scan/security-scan-{timestamp}")
    workspace.mkdir(parents=True, exist_ok=True)

    repo_dir = workspace / "repo"
    if not repo_dir.exists():
        subprocess.run(
            ["git", "clone", "--depth", "1", f"https://github.com/{repo}.git", str(repo_dir)],
            capture_output=True, text=True, timeout=120,
        )

    meta = {
        "repo_url": f"https://github.com/{repo}",
        "repo_name": repo.split("/")[-1],
        "scan_id": f"security-scan-{timestamp}",
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
    }
    (workspace / "scan-metadata.json").write_text(json.dumps(meta, indent=2))

    # Create repo-analysis template
    (workspace / "repo-analysis.md").write_text(
        "# Repository Analysis\n\n"
        "## Repository Overview\n<!-- FILL -->\n\n"
        "## File Inventory\n<!-- FILL -->\n\n"
        "## Technology Stack\n<!-- FILL -->\n\n"
        "## Security-Relevant Patterns\n<!-- FILL -->\n"
    )

    log(f"  Scanner workspace created: {workspace}")
    return str(workspace)


def _invoke_ai_skill(repo, skill_id, name, runtime, sandbox):
    """Run a single AI skill, optionally inside a sandboxed container."""

    # Set up workspace for scanner skill (its hooks don't fire in pipeline mode)
    workspace_path = None
    if name == "semantic-scan":
        workspace_path = _setup_scanner_workspace(repo)

    prompt = (
        f'/security-audit:security-audit is invoking this skill. '
        f'Run it on: {repo}\n'
        f'Skill(skill="{skill_id}", args="{repo}")'
    )

    if workspace_path:
        prompt += f'\n<workspace>{os.path.abspath(workspace_path)}</workspace>'

    claude_args = [
        "claude", "-p", prompt,
        "--allowedTools", "Read,Write,Grep,Glob,Skill,Agent",
        "--max-turns", "100",
    ]

    if sandbox and runtime:
        return _run_in_container(claude_args, runtime, name)
    else:
        if sandbox:
            log(f"  WARNING: No container runtime found, running {name} unsandboxed", level="WARN")
        return _run_locally(claude_args)


def _ensure_sandbox_network(runtime):
    """Create a restricted podman/docker network if it doesn't exist."""
    result = subprocess.run(
        [runtime, "network", "inspect", "security-audit-sandbox"],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        return "security-audit-sandbox"

    result = subprocess.run(
        [runtime, "network", "create", "--internal", "security-audit-sandbox"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        log(f"  WARNING: Failed to create sandbox network: {result.stderr.strip()}", level="WARN")
        return None
    return "security-audit-sandbox"


def _run_in_container(claude_args, runtime, name):
    """Run claude command inside a network-restricted container."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        log("  ANTHROPIC_API_KEY not set, cannot run in container", level="ERROR")
        return False

    container_name = f"security-audit-{name}-{int(time.time())}"

    network = _ensure_sandbox_network(runtime)

    cmd = [
        runtime, "run", "--rm",
        "--name", container_name,
        "--network", network,
        "--memory", "4g",
        "--cpus", "2",
        "-e", "ANTHROPIC_API_KEY",
        AI_SANDBOX_IMAGE,
    ] + claude_args

    try:
        result = run(cmd, check=False, timeout=3600)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        log(f"  {name} timed out (1h), killing container", level="WARN")
        run([runtime, "kill", container_name], check=False)
        return False


def _run_locally(claude_args):
    """Run claude command locally (no sandbox)."""
    try:
        result = run(claude_args, check=False, timeout=3600)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        log("  AI skill timed out (1h)", level="WARN")
        return False


def _collect_ai_output(name, skill_cfg, output_dir):
    """Find and copy AI skill outputs to the scan output directory."""
    out_subdir = skill_cfg["output_dir"]
    dest = Path(output_dir) / "raw" / out_subdir
    dest.mkdir(parents=True, exist_ok=True)

    if name == "adversarial-reviewing":
        # Find FSM orchestrator output in cache
        import glob
        caches = glob.glob("/tmp/adversarial-review-cache-*/outputs/*.md")
        if not caches:
            # Check skill plugin cache
            home = Path.home()
            caches = glob.glob(
                str(home / ".claude/plugins/cache/*/adversarial-reviewing/*/skills/"
                    "adversarial-reviewing/.adversarial-review-cache/*/outputs/*.md")
            )
        if caches:
            # Get the most recent cache dir
            latest_dir = max(set(str(Path(c).parent) for c in caches), key=os.path.getmtime)
            for md in Path(latest_dir).glob("*.md"):
                shutil.copy2(md, dest / md.name)
            log(f"  Collected {len(list(dest.glob('*.md')))} files from FSM cache")
        else:
            log("  WARNING: No FSM orchestrator output found", level="WARN")

    elif name == "semantic-scan":
        # Find security-scan workspace output
        import glob
        workspaces = glob.glob(".security-scan/security-scan-*/security-report.md")
        if not workspaces:
            workspaces = glob.glob(".security-scan/security-scan-*/repo-analysis.md")
        if workspaces:
            ws_dir = str(Path(workspaces[-1]).parent)
            for md in Path(ws_dir).glob("*.md"):
                shutil.copy2(md, dest / md.name)
            log(f"  Collected {len(list(dest.glob('*.md')))} files from workspace")
        else:
            log("  WARNING: No semantic scan output found", level="WARN")


def _run_to_file(cmd_list, output_path, check=False):
    """Run command and write stdout to file. No shell needed."""
    result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=120)
    if result.stdout:
        Path(output_path).write_text(result.stdout)
    elif result.returncode != 0:
        log(f"  WARNING: {cmd_list[1] if len(cmd_list) > 1 else cmd_list[0]} failed (exit {result.returncode})", level="WARN")
        if result.stderr:
            log(f"  {result.stderr[:200]}", level="WARN")
    if check and result.returncode != 0:
        raise RuntimeError(f"Failed: {cmd_list[0]}")
    return result


def step_normalize_dedup_triage(output_dir):
    """Step 4: Normalize, deduplicate, and triage findings."""
    log("Step 4: Normalize, deduplicate, triage")

    _run_to_file(
        ["python3", str(SCRIPTS_DIR / "normalize.py"), f"{output_dir}/raw"],
        f"{output_dir}/normalized-findings.json")
    _run_to_file(
        ["python3", str(SCRIPTS_DIR / "dedup.py"), f"{output_dir}/normalized-findings.json"],
        f"{output_dir}/deduplicated-findings.json")
    _run_to_file(
        ["python3", str(SCRIPTS_DIR / "triage.py"), output_dir],
        f"{output_dir}/triaged-findings.json")

    triaged = Path(output_dir) / "triaged-findings.json"
    if triaged.exists():
        data = json.loads(triaged.read_text())
        if isinstance(data, list):
            log(f"  {len(data)} triaged findings")
        elif isinstance(data, dict):
            log(f"  {data.get('total', '?')} triaged findings")


def step_reports(output_dir):
    """Step 5: Generate all reports."""
    log("Step 5: Generate reports")

    stdout_reports = [
        (["python3", str(SCRIPTS_DIR / "report.py"), output_dir],
         f"{output_dir}/executive-report.md", "executive-report.md"),
        (["python3", str(SCRIPTS_DIR / "report_mustfix.py"), output_dir],
         f"{output_dir}/must-fix-report.md", "must-fix-report.md"),
        (["python3", str(SCRIPTS_DIR / "report_standalone.py"), output_dir],
         f"{output_dir}/security-report.html", "security-report.html"),
        (["python3", str(SCRIPTS_DIR / "report_mustfix.py"), output_dir, "--html"],
         f"{output_dir}/must-fix-report.html", "must-fix-report.html"),
    ]

    dir_reports = [
        (["python3", str(SCRIPTS_DIR / "report_html.py"), output_dir], "MkDocs site"),
        (["python3", str(SCRIPTS_DIR / "report_docx.py"), output_dir], "security-report.docx"),
        (["python3", str(SCRIPTS_DIR / "report_docx.py"), output_dir, "--must-fix"], "must-fix-report.docx"),
    ]

    for cmd, outpath, name in stdout_reports:
        try:
            _run_to_file(cmd, outpath)
            log(f"  {name} OK")
        except Exception as e:
            log(f"  {name} FAILED: {e}", level="WARN")

    for cmd, name in dir_reports:
        try:
            run(cmd, check=False, timeout=120)
            log(f"  {name} OK")
        except Exception as e:
            log(f"  {name} FAILED: {e}", level="WARN")


def step_finalize(output_dir, session_file):
    """Step 6: Update trends and finalize."""
    log("Step 6: Finalize")

    meta_file = Path(output_dir) / "scan-metadata.json"
    if meta_file.exists():
        run(
            ["python3", str(SCRIPTS_DIR / "trends.py"),
             "--add", str(meta_file), "--trends-file", "output/security-trends.json"],
            check=False,
        )

    run(
        ["python3", str(SCRIPTS_DIR / "session_log.py"),
         "finalize", "--session-file", session_file],
        check=False,
    )

    # Print summary
    triaged = Path(output_dir) / "triaged-findings.json"
    if triaged.exists():
        findings = json.loads(triaged.read_text())
        if isinstance(findings, list):
            from collections import Counter
            sev = Counter(f.get("severity", "unknown") for f in findings)
            triage = Counter(
                f.get("triage", {}).get("status", "sast-only")
                if isinstance(f.get("triage"), dict) else "sast-only"
                for f in findings
            )
            log(f"Results: {len(findings)} findings")
            log(f"  Severity: {dict(sev)}")
            log(f"  Triage: {dict(triage)}")

    log(f"Reports in: {output_dir}/")
    for ext in ["html", "md", "docx"]:
        files = list(Path(output_dir).glob(f"*.{ext}"))
        if files:
            log(f"  {ext}: {', '.join(f.name for f in files)}")


def main():
    parser = argparse.ArgumentParser(description="Deterministic security audit pipeline")
    parser.add_argument("repo", help="GitHub org/repo (e.g. opendatahub-io/kube-auth-proxy)")
    parser.add_argument("--branch", default="main", help="Branch to scan")
    parser.add_argument("--skip-ai", action="store_true", help="Skip AI skills (SAST only)")
    parser.add_argument("--no-sandbox", action="store_true", help="Run AI skills without container isolation")
    parser.add_argument("--no-cache", action="store_true", help="Clear AI skill caches, force fresh review")
    parser.add_argument("--reports-only", action="store_true", help="Regenerate reports from existing data")
    parser.add_argument("--scan-dir", help="Existing scan directory for --reports-only")
    args = parser.parse_args()

    repo = args.repo
    if not re.match(r"^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$", repo):
        log(f"Invalid repo format: {repo}. Expected org/repo.", level="ERROR")
        sys.exit(1)
    repo_short = repo.split("/")[-1]

    if args.reports_only:
        if args.scan_dir:
            output_dir = args.scan_dir
        else:
            # Find most recent scan dir
            base = Path(f"output/{repo_short}")
            if base.exists():
                dirs = sorted(base.iterdir(), reverse=True)
                output_dir = str(dirs[0]) if dirs else None
            else:
                output_dir = None
        if not output_dir or not Path(output_dir).exists():
            log("No scan directory found. Run a full scan first.", level="ERROR")
            sys.exit(1)
        log(f"Reports-only mode: {output_dir}")
        step_normalize_dedup_triage(output_dir)
        step_reports(output_dir)
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%S")
    output_dir = f"output/{repo_short}/{timestamp}"

    log(f"Security audit: {repo}")
    log(f"Output: {output_dir}")
    log(f"Sandbox: {'disabled' if args.no_sandbox else 'enabled'}")

    runtime = detect_container_runtime()
    if runtime:
        log(f"Container runtime: {runtime}")
    elif not args.no_sandbox and not args.skip_ai:
        log("No container runtime (podman/docker) found. AI skills will run unsandboxed.", level="WARN")

    session_file = step_init(repo, output_dir)
    step_sast_scan(repo, output_dir, args.branch)

    if not args.skip_ai:
        step_ai_skills(repo, output_dir, session_file,
                       sandbox=not args.no_sandbox, no_cache=args.no_cache)

    step_normalize_dedup_triage(output_dir)
    step_reports(output_dir)
    step_finalize(output_dir, session_file)

    log("Pipeline complete")


if __name__ == "__main__":
    main()
