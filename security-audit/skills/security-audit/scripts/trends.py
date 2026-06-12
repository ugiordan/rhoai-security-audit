#!/usr/bin/env python3
"""Track and display security finding trends across scan runs."""
import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def add_entry(metadata_path, trends_path):
    meta = json.loads(Path(metadata_path).read_text())
    trends_file = Path(trends_path)
    trends = []
    if trends_file.exists():
        try:
            trends = json.loads(trends_file.read_text())
        except (json.JSONDecodeError, OSError):
            trends = []

    repo = meta.get("repo", "unknown")
    commit = meta.get("commit", "unknown")

    if any(e.get("repo") == repo and e.get("commit") == commit for e in trends):
        print(f"Skipped: {repo}@{commit} already in trends", file=sys.stderr)
        return

    findings = meta.get("findings", {})
    severity = {
        "critical": findings.get("critical", 0),
        "high": findings.get("high", 0),
        "medium": findings.get("medium", 0),
        "low": findings.get("low", 0),
        "info": findings.get("info", 0),
    }
    total = findings.get("total_deduped", findings.get("total_raw", sum(severity.values())))

    entry = {
        "date": meta.get("date", datetime.now(timezone.utc).isoformat()),
        "repo": repo,
        "branch": meta.get("branch", "main"),
        "commit": commit,
        "severity": severity,
        "total": total,
        "tools_run": meta.get("tools_run", []),
    }
    trends.append(entry)
    trends_file.parent.mkdir(parents=True, exist_ok=True)
    trends_file.write_text(json.dumps(trends, indent=2))
    print(f"Added: {repo}@{commit[:8]} ({entry['total']} findings)", file=sys.stderr)


def show_trends(trends_path, repo_filter=None, last_n=10):
    trends_file = Path(trends_path)
    if not trends_file.exists():
        print("No trends data found.")
        return

    trends = json.loads(trends_file.read_text())
    if repo_filter:
        trends = [e for e in trends if repo_filter in e.get("repo", "")]
    trends = trends[-last_n:]

    if not trends:
        print("No matching trend entries.")
        return

    print("| Date | Repo | Branch | Commit | Critical | High | Medium | Low | Total | Delta |")
    print("|------|------|--------|--------|----------|------|--------|-----|-------|-------|")

    prev_totals = {}
    for e in trends:
        repo = e.get("repo", "?")
        sev = e.get("severity", {})
        total = e.get("total", 0)
        commit = e.get("commit", "?")[:7]
        date = e.get("date", "?")[:10]
        branch = e.get("branch", "?")

        prev = prev_totals.get(repo)
        if prev is None:
            delta = "-"
        elif total < prev:
            delta = f"v {prev - total}"
        elif total > prev:
            delta = f"^ +{total - prev}"
        else:
            delta = "="
        prev_totals[repo] = total

        print(f"| {date} | {repo} | {branch} | {commit} | "
              f"{sev.get('critical', 0)} | {sev.get('high', 0)} | "
              f"{sev.get('medium', 0)} | {sev.get('low', 0)} | "
              f"{total} | {delta} |")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--add", metavar="METADATA_JSON")
    parser.add_argument("--show", action="store_true")
    parser.add_argument("--trends-file", required=True)
    parser.add_argument("--repo", default=None)
    parser.add_argument("--last", type=int, default=10)
    args = parser.parse_args()

    if args.add:
        add_entry(args.add, args.trends_file)
    elif args.show:
        show_trends(args.trends_file, repo_filter=args.repo, last_n=args.last)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
