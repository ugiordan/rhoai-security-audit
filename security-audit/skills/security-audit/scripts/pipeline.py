#!/usr/bin/env python3
"""Deterministic security audit pipeline.

Removes the LLM from the orchestration loop. Each step is a Python function
that shells out to tools or spawns isolated Claude sessions for AI skills.
AI skills run inside a container with restricted networking.

Usage:
    python3 pipeline.py opendatahub-io/kube-auth-proxy
    python3 pipeline.py opendatahub-io/kube-auth-proxy --skip-ai
    python3 pipeline.py opendatahub-io/kube-auth-proxy --reports-only --scan-dir ~/.security-audit/output/kube-auth-proxy/2026-05-29-142244
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
DEFAULT_OUTPUT_BASE = Path.home() / ".security-audit" / "output"


def detect_harness():
    """Detect whether running under Claude Code or OpenCode.

    Priority: explicit env var > CLAUDE_SKILL_DIR > claude binary > opencode binary.
    Claude Code preferred when both installed (backward compat).
    Fails loudly when nothing is available.
    """
    harness_override = os.environ.get("SECURITY_AUDIT_HARNESS", "").lower()
    if harness_override in ("claude", "opencode"):
        return harness_override

    if os.environ.get("CLAUDE_SKILL_DIR"):
        return "claude"

    if shutil.which("claude"):
        return "claude"

    if shutil.which("opencode"):
        return "opencode"

    log("No AI harness found. Install Claude Code (https://claude.ai/code) "
        "or OpenCode (https://opencode.ai): npm i -g opencode-ai@latest", level="ERROR")
    sys.exit(1)


def resolve_model(args_model):
    """Resolve model from CLI flag, env var, or None (use harness default)."""
    if args_model:
        return args_model
    return os.environ.get("SECURITY_AUDIT_MODEL") or None


def _build_ai_command(harness, prompt, model=None):
    """Build the subprocess command for the detected harness."""
    if harness == "claude":
        plugin_dir = Path.home() / ".claude" / "plugins" / "cache"
        cmd = [
            "claude",
            "--add-dir", str(plugin_dir),
            "-p", prompt,
            "--allowedTools", "Bash,Read,Write,Grep,Glob,Skill,Agent",
            "--max-turns", "100",
        ]
        if model:
            cmd.extend(["--model", model])
        return cmd
    elif harness == "opencode":
        cmd = ["opencode", "run", "--dangerously-skip-permissions"]
        if model:
            cmd.extend(["--model", model])
        cmd.append(prompt)
        return cmd
    else:
        raise ValueError(f"Unknown harness: {harness}")


PROVIDER_ENDPOINTS = {
    "anthropic": "api.anthropic.com",
    "openai": "api.openai.com",
    "google": "generativelanguage.googleapis.com",
    "google-vertex": "us-east5-aiplatform.googleapis.com",
    "google-vertex-anthropic": "us-east5-aiplatform.googleapis.com",
}

OPENSHELL_POLICY_TEMPLATE = """version: 1
filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
    - /lib
    - /proc
    - /dev/urandom
    - /etc
  read_write:
    - /tmp
    - /dev/null
network_policies:
  llm_api:
    name: llm-api
    endpoints:
      - host: {provider_host}
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
        request_body_credential_rewrite: true
    binaries:
      - path: /usr/local/bin/claude
      - path: /usr/local/bin/opencode
      - path: /usr/bin/node
      - path: /usr/bin/curl
  gcp_auth:
    name: gcp-auth
    endpoints:
      - host: oauth2.googleapis.com
        port: 443
        access: full
      - host: accounts.google.com
        port: 443
        access: full
    binaries:
      - path: /usr/local/bin/opencode
      - path: /usr/bin/node
      - path: /usr/bin/curl
"""


def _generate_openshell_policy(model):
    """Generate OpenShell network policy for the model's provider."""
    if not model:
        return OPENSHELL_POLICY_TEMPLATE.format(provider_host="api.anthropic.com")

    provider = model.split("/")[0] if "/" in model else model
    host = PROVIDER_ENDPOINTS.get(provider)

    if not host:
        host = os.environ.get("SECURITY_AUDIT_PROVIDER_HOST")
        if not host:
            known = ", ".join(PROVIDER_ENDPOINTS.keys())
            log(f"Unknown provider '{provider}'. Set SECURITY_AUDIT_PROVIDER_HOST "
                f"or use a known provider ({known}).", level="ERROR")
            sys.exit(1)

    return OPENSHELL_POLICY_TEMPLATE.format(provider_host=host)


AI_SKILLS = [
    {
        "name": "adversarial-reviewing",
        "skill": "adversarial-reviewing:adversarial-reviewing",
        "verify_glob": "**/outputs/REPORT.md",
        "output_dir": "adversarial-reviewing",
    },
    {
        "name": "semantic-scan",
        "skill": "semantic-scan:audit",
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


def _ensure_openshell():
    """Install OpenShell if not present, start gateway if needed."""
    if not shutil.which("openshell"):
        log("  Installing OpenShell...")
        if shutil.which("brew"):
            subprocess.run(
                ["brew", "install", "openshell"],
                capture_output=True, text=True, timeout=120,
            )
        elif shutil.which("uv"):
            subprocess.run(
                ["uv", "tool", "install", "-U", "openshell"],
                capture_output=True, text=True, timeout=120,
            )
        elif shutil.which("pip3"):
            subprocess.run(
                ["pip3", "install", "--quiet", "openshell"],
                capture_output=True, text=True, timeout=120,
            )
        else:
            log("  Cannot install OpenShell (no brew, uv, or pip3)", level="WARN")
            return False

    if not shutil.which("openshell"):
        log("  OpenShell install failed", level="WARN")
        return False

    if _openshell_connected():
        return True

    # Gateway not connected, try to start it
    log("  Starting OpenShell gateway...")
    if shutil.which("brew"):
        subprocess.run(
            ["brew", "services", "start", "openshell"],
            capture_output=True, text=True, timeout=30,
        )
    else:
        gw_bin = Path("/opt/homebrew/opt/openshell/libexec/openshell-gateway-homebrew-service")
        if gw_bin.exists():
            subprocess.Popen(
                [str(gw_bin)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
    time.sleep(5)

    if _openshell_connected():
        log("  OpenShell gateway started")
        return True

    log("  OpenShell gateway failed to start", level="WARN")
    return False


def _openshell_connected():
    """Check if OpenShell gateway is connected."""
    result = subprocess.run(
        ["openshell", "status"], capture_output=True, text=True, timeout=10,
    )
    return "Connected" in (result.stdout or "")


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
    import tempfile
    tmpdir = os.environ.get("TMPDIR", tempfile.gettempdir())
    patterns = [
        os.path.join(tmpdir, "adversarial-review-cache-*"),
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


def _resolve_arch_context(arch_context, repo, output_dir):
    """Resolve --arch-context to a local directory path.

    Accepts:
      - Local path: /tmp/arch-output (used as-is if it exists)
      - GitHub repo: owner/repo (downloads matching artifact via gh CLI)
    """
    if not arch_context:
        return None

    # Local path
    if os.path.isdir(arch_context):
        log(f"  Architecture context (local): {arch_context}")
        return arch_context

    # GitHub repo reference (contains / but not a local path)
    if "/" in arch_context and not arch_context.startswith("/"):
        repo_short = repo.split("/")[-1]
        ctx_dir = Path(output_dir) / "raw" / "arch-context"

        try:
            # Artifact naming: {prefix}-{org}-{repo}
            # Try exact org match first, then search by repo name suffix
            repo_org = repo.split("/")[0] if "/" in repo else ""
            artifact_name = ""

            for prefix in ["odh", "rhoai"]:
                candidate = f"{prefix}-{repo_org}-{repo_short}"
                result = subprocess.run(
                    ["gh", "api",
                     f"repos/{arch_context}/actions/artifacts?name={candidate}",
                     "--jq", ".artifacts[0].name"],
                    capture_output=True, text=True, timeout=15,
                )
                name = result.stdout.strip()
                if name and name != "null":
                    artifact_name = name
                    break

            # Fallback: paginated search by repo name suffix (handles fork/upstream mismatch)
            if not artifact_name:
                result = subprocess.run(
                    ["gh", "api", f"repos/{arch_context}/actions/artifacts",
                     "--paginate",
                     "--jq", f'.artifacts[] | select(.name | endswith("-{repo_short}")) | .name'],
                    capture_output=True, text=True, timeout=30,
                )
                names = [n for n in (result.stdout or "").strip().split("\n") if n]
                if names:
                    odh = [n for n in names if n.startswith("odh-")]
                    artifact_name = odh[0] if odh else names[0]
            if not artifact_name:
                log(f"  No architecture artifact for {repo_short} in {arch_context}", level="WARN")
                return None

            ctx_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["gh", "run", "download", "--repo", arch_context,
                 "--name", artifact_name, "--dir", str(ctx_dir)],
                capture_output=True, text=True, timeout=60,
            )

            for p in ctx_dir.rglob("component-architecture.json"):
                log(f"  Architecture context (downloaded): {artifact_name}")
                return str(p.parent)
        except Exception as e:
            log(f"  Failed to fetch arch context from {arch_context}: {e}", level="WARN")
        return None

    log(f"  Architecture context path not found: {arch_context}", level="WARN")
    return None


def step_ai_skills(repo, output_dir, session_file, sandbox=True, no_cache=False, arch_context=None, harness="claude", model=None):
    """Step 3: Invoke AI skills in parallel."""
    log("Step 3: AI skills (parallel)")
    if no_cache:
        removed = _clear_ai_caches()
        log(f"  Cleared {removed} AI skill caches (--no-cache)")
    arch_context = _resolve_arch_context(arch_context, repo, output_dir)
    runtime = detect_container_runtime() if sandbox else None

    skills = [dict(s) for s in AI_SKILLS]

    def _run_one_skill(skill_cfg):
        name = skill_cfg["name"]
        skill_id = skill_cfg["skill"]
        log(f"  Invoking {name}...")
        run(
            ["python3", str(SCRIPTS_DIR / "session_log.py"), "agent",
             "--session-file", session_file, "--name", name, "--phase", "started"],
            check=False,
        )
        start = time.time()
        result = _invoke_ai_skill(repo, skill_id, name, runtime, sandbox, arch_context, harness=harness, model=model)
        duration = time.time() - start
        if result:
            if isinstance(result, str):
                skill_cfg["_fsm_cache_dir"] = result
            _collect_ai_output(name, skill_cfg, output_dir)
            log(f"  {name} complete ({duration:.0f}s)")
        else:
            log(f"  {name} FAILED ({duration:.0f}s)", level="WARN")
        run(
            ["python3", str(SCRIPTS_DIR / "session_log.py"), "agent",
             "--session-file", session_file, "--name", name, "--phase", "completed"],
            check=False,
        )

    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=len(skills)) as pool:
        futures = {pool.submit(_run_one_skill, s): s["name"] for s in skills}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                log(f"  {futures[future]} error: {e}", level="WARN")


def _setup_scanner_workspace(repo):
    """Create workspace for semantic-scan since its hooks don't fire in pipeline mode."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%S")
    workspace = Path(f".security-scan/security-scan-{timestamp}")
    workspace.mkdir(parents=True, exist_ok=True)

    repo_dir = workspace / "repo"
    if not repo_dir.exists():
        subprocess.run(
            ["git", "clone", "--depth", "1", "--no-recurse-submodules",
             f"https://github.com/{repo}.git", str(repo_dir)],
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


def _find_adversarial_skill_dir():
    """Find the adversarial-reviewing skill directory in plugin cache."""
    plugin_cache = Path.home() / ".claude" / "plugins" / "cache"
    for pattern in [
        "ugiordan-adversarial-reviewing/adversarial-reviewing/*/skills/adversarial-reviewing",
        "ugiordan-security-audit/adversarial-reviewing/*/skills/adversarial-reviewing",
    ]:
        import glob
        matches = glob.glob(str(plugin_cache / pattern))
        if matches:
            skill_dir = max(matches)
            if (Path(skill_dir) / "scripts" / "orchestrator" / "__main__.py").exists():
                return skill_dir
    return None


def _run_adversarial_reviewing(repo, arch_context=None, harness="claude", model=None, sandbox=False):
    """Drive the adversarial-reviewing FSM directly via Python scripts.

    Instead of asking an LLM to invoke the skill (unreliable), we call
    the orchestrator commands directly and dispatch agents with focused prompts.
    """
    skill_dir = _find_adversarial_skill_dir()
    if not skill_dir:
        log("  adversarial-reviewing skill not found in plugin cache", level="ERROR")
        return False

    # Clean stale state
    for stale in [Path("artifacts"), Path(".adversarial-review-cache")]:
        if stale.exists():
            shutil.rmtree(stale, ignore_errors=True)

    # Clone target repo so the orchestrator has a real source_root
    import tempfile
    repo_clone_dir = tempfile.mkdtemp(prefix="adversarial-review-repo-")
    clone_result = subprocess.run(
        ["git", "clone", "--depth", "1", "--no-recurse-submodules",
         f"https://github.com/{repo}.git", repo_clone_dir],
        capture_output=True, text=True, timeout=120,
    )
    if clone_result.returncode != 0:
        log(f"  Failed to clone {repo} for adversarial review: {clone_result.stderr[:200]}", level="ERROR")
        shutil.rmtree(repo_clone_dir, ignore_errors=True)
        return False

    # Remove directories that bloat scope (Go module cache, build output)
    for bloat_dir in [".gopath-loader", ".gopath", "vendor", "_output", "bin"]:
        bloat_path = Path(repo_clone_dir) / bloat_dir
        if bloat_path.exists():
            shutil.rmtree(bloat_path, ignore_errors=True)

    env = os.environ.copy()
    env["CLAUDE_SKILL_DIR"] = skill_dir
    stub_dir = None

    # Step 1: Init (pass clone path as target so orchestrator scopes the repo, not itself)
    skill_args = [repo_clone_dir, "--no-budget"]
    if arch_context:
        skill_args.extend(["--context", f"architecture={arch_context}"])

    # Start OpenCode server for fast agent dispatch (avoids per-invocation overhead)
    opencode_server = None
    opencode_proc = None
    if harness == "opencode" and shutil.which("opencode"):
        import socket
        with socket.socket() as s:
            s.bind(("", 0))
            oc_port = s.getsockname()[1]
        server_env = os.environ.copy()
        server_env.update({
            k: env[k] for k in ["GOOGLE_CLOUD_PROJECT", "VERTEX_LOCATION",
                                 "ANTHROPIC_API_KEY", "ANTHROPIC_VERTEX_PROJECT_ID"]
            if k in env
        })
        opencode_proc = subprocess.Popen(
            ["opencode", "serve", "--port", str(oc_port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=server_env,
        )
        time.sleep(3)
        if opencode_proc.poll() is None:
            opencode_server = f"http://localhost:{oc_port}"
            log(f"  OpenCode server started on port {oc_port}")
        else:
            log("  OpenCode server failed to start, falling back to claude", level="WARN")
            opencode_proc = None

    def _cleanup_repo_clone():
        shutil.rmtree(repo_clone_dir, ignore_errors=True)
        if stub_dir:
            shutil.rmtree(stub_dir, ignore_errors=True)
        if opencode_proc:
            opencode_proc.terminate()
            opencode_proc.wait(timeout=5)

    log("  FSM init...")
    result = subprocess.run(
        ["python3", "-m", "scripts.orchestrator", "init"] + skill_args,
        capture_output=True, text=True, timeout=60,
        cwd=skill_dir, env=env,
    )
    if result.returncode != 0:
        log(f"  orchestrator init failed: {result.stderr[:300]}", level="ERROR")
        _cleanup_repo_clone()
        return False

    init_data = json.loads(result.stdout)
    cache_dir = init_data["cache_dir"]
    log(f"  FSM cache: {cache_dir}")

    # Step 2: Confirm scope (populates cache, can take minutes for large repos)
    log("  FSM confirm (populating cache)...")
    result = subprocess.run(
        ["python3", "-m", "scripts.orchestrator", "confirm", "--cache-dir", cache_dir],
        capture_output=True, text=True, timeout=600,
        cwd=skill_dir, env=env,
    )
    if result.returncode != 0:
        log(f"  orchestrator confirm failed: {result.stderr[:300]}", level="ERROR")
        _cleanup_repo_clone()
        return False

    # Step 3: Dispatch loop
    max_rounds = 20
    for round_num in range(max_rounds):
        dispatch_file = Path(cache_dir) / "dispatch.json"
        if not dispatch_file.exists():
            log("  dispatch.json not found, FSM may have failed", level="ERROR")
            _cleanup_repo_clone()
            return False

        dispatch = json.loads(dispatch_file.read_text())

        if dispatch.get("done"):
            log(f"  FSM complete after {round_num} rounds")
            _cleanup_repo_clone()
            return cache_dir

        if dispatch.get("action") == "ask_user":
            log("  FSM requested user confirmation (auto-confirming)...")
            result = subprocess.run(
                ["python3", "-m", "scripts.orchestrator", "confirm", "--cache-dir", cache_dir],
                capture_output=True, text=True, timeout=600,
                cwd=skill_dir, env=env,
            )
            if result.returncode != 0:
                log(f"  confirm failed: {result.stderr[:300]}", level="ERROR")
                _cleanup_repo_clone()
                return False
            continue

        agents = dispatch.get("agents", [])
        if not agents:
            log(f"  No agents in dispatch (round {round_num}), advancing...", level="WARN")
        else:
            phase = dispatch.get("phase", "unknown")
            parallel = dispatch.get("parallel", False)
            log(f"  Dispatching {len(agents)} agents ({phase}, parallel={parallel})")

            if parallel and len(agents) > 1:
                from concurrent.futures import ThreadPoolExecutor, as_completed
                with ThreadPoolExecutor(max_workers=min(len(agents), 5)) as pool:
                    futures = {
                        pool.submit(_dispatch_agent, agent, harness, model, sandbox, opencode_server): agent["id"]
                        for agent in agents
                    }
                    for future in as_completed(futures):
                        agent_id = futures[future]
                        try:
                            future.result()
                            log(f"    {agent_id} done")
                        except Exception as e:
                            log(f"    {agent_id} failed: {e}", level="WARN")
            else:
                for agent in agents:
                    try:
                        _dispatch_agent(agent, harness, model, sandbox, opencode_server)
                        log(f"    {agent['id']} done")
                    except Exception as e:
                        log(f"    {agent['id']} failed: {e}", level="WARN")

        # Advance FSM
        result = subprocess.run(
            ["python3", "-m", "scripts.orchestrator", "next", "--cache-dir", cache_dir],
            capture_output=True, text=True, timeout=120,
            cwd=skill_dir, env=env,
        )
        if result.returncode != 0:
            log(f"  orchestrator next failed: {result.stderr[:300]}", level="ERROR")
            _cleanup_repo_clone()
            return False

    log("  FSM did not complete within max rounds", level="WARN")
    _cleanup_repo_clone()
    return False


def _dispatch_agent(agent, harness, model, sandbox=False, opencode_server=None):
    """Dispatch a single review agent.

    When opencode_server is set (e.g. "http://localhost:4096"), uses
    opencode run --attach for fast dispatch without per-invocation overhead.
    Otherwise falls back to claude -p or opencode run standalone.
    Sandbox mode uploads dispatch dir into OpenShell container.
    """
    dispatch_path = agent.get("dispatch_path", "")
    agent_id = agent.get("id", "unknown")

    prompt = (
        f"You are a code review agent ({agent_id}). "
        f"Read all files in this directory starting with agent-instructions.md. "
        f"Follow the instructions exactly. Write your output to output.md. "
        f"Do NOT return a summary. Your work is complete when output.md exists."
    )

    if opencode_server:
        cmd = [
            "opencode", "run",
            "--attach", opencode_server,
            "--dir", dispatch_path,
            "--dangerously-skip-permissions",
        ]
        if model:
            cmd.extend(["--model", model])
        cmd.append(prompt)
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=1800,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Agent {agent_id} exited {result.returncode}")
    else:
        cmd = _build_ai_command("claude" if shutil.which("claude") else harness, prompt, model=model)
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=1800, cwd=dispatch_path,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Agent {agent_id} exited {result.returncode}")


def _invoke_ai_skill(repo, skill_id, name, _runtime, sandbox, arch_context=None, harness="claude", model=None):
    """Run a single AI skill, optionally inside an OpenShell sandbox."""

    if name == "adversarial-reviewing":
        return _run_adversarial_reviewing(repo, arch_context, harness, model, sandbox)

    # Set up workspace for scanner skill (its hooks don't fire in pipeline mode)
    workspace_path = None
    if name == "semantic-scan":
        workspace_path = _setup_scanner_workspace(repo)

    skill_args = repo
    prompt = (
        f'Run this skill on the repository {repo}. '
        f'Use the Skill tool: Skill(skill="{skill_id}", args="{skill_args}")'
    )

    if workspace_path:
        prompt += f'\n<workspace>{os.path.abspath(workspace_path)}</workspace>'

    ai_cmd = _build_ai_command(harness, prompt, model=model)

    if sandbox:
        if _ensure_openshell():
            return _run_in_openshell(ai_cmd, name, model=model)
        else:
            log(f"  OpenShell not available. Use --no-sandbox to run without isolation.", level="ERROR")
            return False
    return _run_locally(ai_cmd)


def _run_in_openshell(ai_cmd, name, model=None, extra_upload=None):
    """Run AI harness command inside an OpenShell sandbox with dynamic network policy.

    extra_upload: optional (host_path, sandbox_name) tuple. The host_path directory
    is copied into the staging dir as sandbox_name, so it appears at
    /sandbox/<staging>/<sandbox_name>/ inside the container.
    """
    import tempfile

    policy_content = _generate_openshell_policy(model)
    sandbox_name = f"security-audit-{name}-{int(time.time())}"

    # Write dynamic policy to a temp file
    policy_fd, policy_path = tempfile.mkstemp(suffix=".yaml", prefix="openshell-policy-")
    try:
        with os.fdopen(policy_fd, "w") as f:
            f.write(policy_content)

        import shlex

        # Build env exports for the sandbox command (non-sensitive only)
        env_exports = []
        for var in ["GOOGLE_CLOUD_PROJECT", "ANTHROPIC_VERTEX_PROJECT_ID",
                     "VERTEX_LOCATION"]:
            val = os.environ.get(var)
            if val:
                env_exports.append(f"export {var}={shlex.quote(val)}")

        # Stage files to upload into sandbox (single --upload flag, secure dir)
        upload_dir = tempfile.mkdtemp(prefix="openshell-upload-")
        os.chmod(upload_dir, 0o700)
        upload_dir_name = Path(upload_dir).name
        upload_args = []

        # GCP ADC credentials
        adc_path = Path.home() / ".config" / "gcloud" / "application_default_credentials.json"
        if adc_path.exists():
            shutil.copy2(adc_path, Path(upload_dir) / "application_default_credentials.json")
            env_exports.append(f"export GOOGLE_APPLICATION_CREDENTIALS=/sandbox/{upload_dir_name}/application_default_credentials.json")

        # API key via env (not in command string)
        sandbox_env = {}
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if api_key:
            sandbox_env["ANTHROPIC_API_KEY"] = api_key

        # OpenCode config (needed for provider discovery inside sandbox)
        oc_dir = Path.home() / ".config" / "opencode"
        if oc_dir.exists():
            dest_oc = Path(upload_dir) / "opencode-config"
            dest_oc.mkdir(exist_ok=True)
            for f in oc_dir.iterdir():
                if f.is_file():
                    shutil.copy2(f, dest_oc / f.name)
            env_exports.append(f"mkdir -p /sandbox/.config && cp -r /sandbox/{upload_dir_name}/opencode-config /sandbox/.config/opencode")

        # Extra upload (dispatch directory for sandboxed agents)
        if extra_upload:
            host_path, sandbox_dest = extra_upload
            dest = Path(upload_dir) / sandbox_dest
            shutil.copytree(host_path, dest, dirs_exist_ok=True)
            sandbox_full_path = f"/sandbox/{upload_dir_name}/{sandbox_dest}"
            ai_cmd = [arg.replace("{DISPATCH_DIR}", sandbox_full_path) for arg in ai_cmd]

        if any(Path(upload_dir).iterdir()):
            upload_args = ["--upload", upload_dir]

        # Wrap the AI command with env setup (use shlex.quote for safety)
        if env_exports:
            escaped_cmd = " ".join(shlex.quote(a) for a in ai_cmd)
            wrapped_cmd = f"{' && '.join(env_exports)} && {escaped_cmd}"
            sandbox_ai_cmd = ["sh", "-c", wrapped_cmd]
        else:
            sandbox_ai_cmd = ai_cmd

        keep_sandbox = extra_upload is not None
        cmd = [
            "openshell", "sandbox", "create",
            "--name", sandbox_name,
            "--auto-providers",
            "--policy", policy_path,
        ]
        if not keep_sandbox:
            cmd.append("--no-keep")
        cmd += upload_args + ["--"] + sandbox_ai_cmd

        try:
            result = run(cmd, check=False, timeout=3600)
            success = result.returncode == 0

            # Download agent output from sandbox back to host
            if keep_sandbox and extra_upload:
                host_path, sandbox_dest = extra_upload
                sandbox_output = f"/sandbox/{upload_dir_name}/{sandbox_dest}/output.md"
                dl_result = subprocess.run(
                    ["openshell", "sandbox", "download", sandbox_name,
                     sandbox_output, str(Path(host_path) / "output.md")],
                    capture_output=True, text=True, timeout=30,
                )
                if dl_result.returncode != 0:
                    log(f"    Failed to download output from sandbox: {dl_result.stderr[:200]}", level="WARN")

                subprocess.run(
                    ["openshell", "sandbox", "delete", sandbox_name],
                    capture_output=True, text=True, timeout=30,
                )

            return success
        except subprocess.TimeoutExpired:
            log(f"  {name} timed out (1h), deleting sandbox", level="WARN")
            subprocess.run(
                ["openshell", "sandbox", "delete", sandbox_name],
                capture_output=True, text=True, timeout=30,
            )
            return False
    finally:
        try:
            os.unlink(policy_path)
        except OSError:
            pass
        if upload_dir:
            shutil.rmtree(upload_dir, ignore_errors=True)


def _run_locally(ai_cmd):
    """Run AI harness command locally (no sandbox) with progress logging."""
    import threading

    process = subprocess.Popen(
        ai_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    stop = threading.Event()
    def ticker():
        mins = 0
        while not stop.wait(60):
            mins += 1
            log(f"    AI skill running... ({mins}m elapsed)")
    t = threading.Thread(target=ticker, daemon=True)
    t.start()

    try:
        process.communicate(timeout=3600)
        stop.set()
        return process.returncode == 0
    except subprocess.TimeoutExpired:
        stop.set()
        process.kill()
        log("  AI skill timed out (1h)", level="WARN")
        return False


def _collect_ai_output(name, skill_cfg, output_dir):
    """Find and copy AI skill outputs to the scan output directory."""
    out_subdir = skill_cfg["output_dir"]
    dest = Path(output_dir) / "raw" / out_subdir
    dest.mkdir(parents=True, exist_ok=True)

    if name == "adversarial-reviewing":
        collected = False
        fsm_cache = skill_cfg.get("_fsm_cache_dir", "")

        # Primary: artifacts/ inside the FSM cache dir
        if fsm_cache:
            for subdir in ["artifacts", "outputs"]:
                src = Path(fsm_cache) / subdir
                if src.exists():
                    for md in src.glob("*.md"):
                        shutil.copy2(md, dest / md.name)
            if list(dest.glob("*.md")):
                collected = True
                log(f"  Collected {len(list(dest.glob('*.md')))} files from FSM cache")

        # Fallback: artifacts/ in cwd (interactive mode)
        if not collected:
            artifacts_dir = Path("artifacts")
            if artifacts_dir.exists() and list(artifacts_dir.glob("*.md")):
                for md in artifacts_dir.glob("*.md"):
                    shutil.copy2(md, dest / md.name)
                collected = True
                log(f"  Collected {len(list(dest.glob('*.md')))} files from artifacts/")
                shutil.rmtree(artifacts_dir, ignore_errors=True)

        if not collected:
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
             "--add", str(meta_file), "--trends-file", str(DEFAULT_OUTPUT_BASE.parent / "security-trends.json")],
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
    parser.add_argument("--arch-context", help="Path to architecture-analyzer output directory")
    parser.add_argument("--model", default=None,
                        help="LLM model (e.g. anthropic/claude-sonnet-4-6, openai/gpt-4o)")
    parser.add_argument("--reports-only", action="store_true", help="Regenerate reports from existing data")
    parser.add_argument("--scan-dir", help="Existing scan directory for --reports-only")
    args = parser.parse_args()

    repo = args.repo
    if not re.match(r"^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$", repo) or ".." in repo:
        log(f"Invalid repo format: {repo}. Expected org/repo.", level="ERROR")
        sys.exit(1)
    repo_short = repo.split("/")[-1]

    harness = detect_harness()
    model = resolve_model(args.model)
    log(f"Harness: {harness}")
    if model:
        log(f"Model: {model}")

    if args.reports_only:
        if args.scan_dir:
            output_dir = args.scan_dir
        else:
            base_override = os.environ.get("SECURITY_AUDIT_OUTPUT_DIR", "")
            base = Path(base_override) / repo_short if base_override else DEFAULT_OUTPUT_BASE / repo_short
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
    env_override = os.environ.get("SECURITY_AUDIT_OUTPUT_DIR", "")
    base = Path(env_override) if env_override else DEFAULT_OUTPUT_BASE
    output_dir = str(base / repo_short / timestamp)

    log(f"Security audit: {repo}")
    log(f"Output: {output_dir}")
    log(f"Sandbox: {'disabled' if args.no_sandbox else 'enabled'}")

    runtime = detect_container_runtime()
    if runtime:
        log(f"Container runtime: {runtime}")
    elif not args.no_sandbox and not args.skip_ai:
        log("No container runtime (podman/docker) found. Sandbox requires OpenShell or --no-sandbox.", level="INFO")

    session_file = step_init(repo, output_dir)

    if args.skip_ai:
        step_sast_scan(repo, output_dir, args.branch)
    else:
        # Step 2: SAST and AI skills run in parallel
        from concurrent.futures import ThreadPoolExecutor, as_completed

        log("Step 2: SAST scan + AI skills (parallel)")
        failed = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            sast_future = pool.submit(step_sast_scan, repo, output_dir, args.branch)
            ai_future = pool.submit(
                step_ai_skills, repo, output_dir, session_file,
                not args.no_sandbox, args.no_cache, args.arch_context,
                harness, model,
            )
            for name, future in [("SAST", sast_future), ("AI skills", ai_future)]:
                try:
                    future.result()
                except Exception as e:
                    log(f"  {name} FAILED: {e}", level="ERROR")
                    failed.append(name)

        if "SAST" in failed:
            log("SAST scan failed. Cannot produce reports without scan data.", level="ERROR")
            step_finalize(output_dir, session_file)
            sys.exit(1)

    step_normalize_dedup_triage(output_dir)
    step_reports(output_dir)
    step_finalize(output_dir, session_file)

    log("Pipeline complete")


if __name__ == "__main__":
    main()
