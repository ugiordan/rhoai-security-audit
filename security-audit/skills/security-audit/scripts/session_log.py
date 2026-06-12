#!/usr/bin/env python3
"""Session logging for security-audit skill.

Tracks every pipeline step: timing, inputs, outputs, model reasoning,
agent dispatches. Saves a structured JSON log + human-readable markdown
transcript.

Usage:
    # Initialize a session
    python3 session_log.py init --repo org/repo --output-dir ./output/repo/2026-05-08

    # Log a step
    python3 session_log.py step --session-file <path> \
        --name "Run semgrep" --status ok \
        --detail "Found 110 findings" \
        --reasoning "Chose --config auto for broad coverage"

    # Log an AI agent dispatch
    python3 session_log.py agent --session-file <path> \
        --name "adversarial-reviewing" --phase "security-auditor" \
        --prompt-file /tmp/prompt.md --output-file /tmp/output.md \
        --model claude-sonnet-4-6 --duration 45.2

    # Finalize and write transcript
    python3 session_log.py finalize --session-file <path>
"""
import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path


def init_session(repo, output_dir):
    session = {
        "repo": repo,
        "output_dir": output_dir,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "steps": [],
        "agents": [],
        "summary": {},
    }
    session_file = Path(output_dir) / "session-log.json"
    session_file.parent.mkdir(parents=True, exist_ok=True)
    session_file.write_text(json.dumps(session, indent=2))
    print(json.dumps({"session_file": str(session_file)}))


def log_step(session_file, name, status, detail="", reasoning="", duration=0):
    path = Path(session_file)
    session = json.loads(path.read_text())
    session["steps"].append({
        "name": name,
        "status": status,
        "detail": detail,
        "reasoning": reasoning,
        "duration_s": duration,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    path.write_text(json.dumps(session, indent=2))


def log_agent(session_file, name, phase, prompt_file="", output_file="",
              model="", duration=0, findings_count=0):
    path = Path(session_file)
    session = json.loads(path.read_text())

    prompt_text = ""
    if prompt_file and Path(prompt_file).exists():
        prompt_text = Path(prompt_file).read_text()[:2000]

    output_text = ""
    if output_file and Path(output_file).exists():
        output_text = Path(output_file).read_text()[:5000]

    session["agents"].append({
        "name": name,
        "phase": phase,
        "model": model,
        "prompt_preview": prompt_text[:500] if prompt_text else "",
        "output_preview": output_text[:1000] if output_text else "",
        "prompt_file": prompt_file,
        "output_file": output_file,
        "findings_count": findings_count,
        "duration_s": duration,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    path.write_text(json.dumps(session, indent=2))


def finalize(session_file):
    path = Path(session_file)
    session = json.loads(path.read_text())
    session["finished_at"] = datetime.now(timezone.utc).isoformat()

    started = datetime.fromisoformat(session["started_at"])
    finished = datetime.fromisoformat(session["finished_at"])
    session["total_duration_s"] = round((finished - started).total_seconds(), 1)
    session["summary"] = {
        "steps_total": len(session["steps"]),
        "steps_ok": sum(1 for s in session["steps"] if s["status"] == "ok"),
        "steps_failed": sum(1 for s in session["steps"] if s["status"] == "error"),
        "steps_skipped": sum(1 for s in session["steps"] if s["status"] == "skipped"),
        "agents_dispatched": len(session["agents"]),
        "total_duration_s": session["total_duration_s"],
    }
    path.write_text(json.dumps(session, indent=2))

    transcript = _build_transcript(session)
    transcript_path = path.parent / "session-transcript.md"
    transcript_path.write_text(transcript)

    print(json.dumps(session["summary"], indent=2))


def _build_transcript(session):
    lines = []
    lines.append(f"# Security Audit Session Log")
    lines.append(f"")
    lines.append(f"**Repo:** {session['repo']}")
    lines.append(f"**Started:** {session['started_at']}")
    lines.append(f"**Finished:** {session.get('finished_at', 'in progress')}")
    lines.append(f"**Duration:** {session.get('total_duration_s', '?')}s")
    lines.append(f"")

    lines.append(f"## Pipeline Steps")
    lines.append(f"")
    for i, step in enumerate(session["steps"], 1):
        icon = {"ok": "v", "error": "X", "skipped": "-"}.get(step["status"], "?")
        lines.append(f"### {i}. [{icon}] {step['name']}")
        if step.get("duration_s"):
            lines.append(f"*Duration: {step['duration_s']}s*")
        if step.get("detail"):
            lines.append(f"")
            lines.append(f"{step['detail']}")
        if step.get("reasoning"):
            lines.append(f"")
            lines.append(f"**Reasoning:** {step['reasoning']}")
        lines.append(f"")

    if session["agents"]:
        lines.append(f"## AI Agent Dispatches")
        lines.append(f"")
        for i, agent in enumerate(session["agents"], 1):
            lines.append(f"### Agent {i}: {agent['name']} ({agent['phase']})")
            if agent.get("model"):
                lines.append(f"*Model: {agent['model']}, Duration: {agent.get('duration_s', '?')}s*")
            if agent.get("findings_count"):
                lines.append(f"*Findings: {agent['findings_count']}*")
            if agent.get("prompt_preview"):
                lines.append(f"")
                lines.append(f"<details><summary>Prompt (preview)</summary>")
                lines.append(f"")
                lines.append(f"```")
                lines.append(agent["prompt_preview"])
                lines.append(f"```")
                lines.append(f"</details>")
            if agent.get("output_preview"):
                lines.append(f"")
                lines.append(f"<details><summary>Output (preview)</summary>")
                lines.append(f"")
                lines.append(f"```")
                lines.append(agent["output_preview"])
                lines.append(f"```")
                lines.append(f"</details>")
            lines.append(f"")

    s = session.get("summary", {})
    if s:
        lines.append(f"## Summary")
        lines.append(f"")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Steps completed | {s.get('steps_ok', 0)}/{s.get('steps_total', 0)} |")
        lines.append(f"| Steps failed | {s.get('steps_failed', 0)} |")
        lines.append(f"| Steps skipped | {s.get('steps_skipped', 0)} |")
        lines.append(f"| AI agents dispatched | {s.get('agents_dispatched', 0)} |")
        lines.append(f"| Total duration | {s.get('total_duration_s', '?')}s |")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")

    p_init = sub.add_parser("init")
    p_init.add_argument("--repo", required=True)
    p_init.add_argument("--output-dir", required=True)

    p_step = sub.add_parser("step")
    p_step.add_argument("--session-file", required=True)
    p_step.add_argument("--name", required=True)
    p_step.add_argument("--status", required=True, choices=["ok", "error", "skipped"])
    p_step.add_argument("--detail", default="")
    p_step.add_argument("--reasoning", default="")
    p_step.add_argument("--duration", type=float, default=0)

    p_agent = sub.add_parser("agent")
    p_agent.add_argument("--session-file", required=True)
    p_agent.add_argument("--name", required=True)
    p_agent.add_argument("--phase", required=True)
    p_agent.add_argument("--prompt-file", default="")
    p_agent.add_argument("--output-file", default="")
    p_agent.add_argument("--model", default="")
    p_agent.add_argument("--duration", type=float, default=0)
    p_agent.add_argument("--findings-count", type=int, default=0)

    p_fin = sub.add_parser("finalize")
    p_fin.add_argument("--session-file", required=True)

    args = parser.parse_args()
    if args.command == "init":
        init_session(args.repo, args.output_dir)
    elif args.command == "step":
        log_step(args.session_file, args.name, args.status,
                 args.detail, args.reasoning, args.duration)
    elif args.command == "agent":
        log_agent(args.session_file, args.name, args.phase,
                  args.prompt_file, args.output_file,
                  args.model, args.duration, args.findings_count)
    elif args.command == "finalize":
        finalize(args.session_file)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
