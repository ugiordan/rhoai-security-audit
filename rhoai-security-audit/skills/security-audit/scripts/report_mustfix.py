#!/usr/bin/env python3
"""Generate must-fix security report matching ProdSec Google Docs format.

Produces a structured markdown report focused on actionable fixes:
- Scope header (repo, branch, scan date, tools)
- Fix N: Title (SEVERITY) with risk, files, line numbers
- Dismissed findings with reasoning
- Summary table with effort estimates and recommended fix order

Usage:
    python3 report_mustfix.py <scan-dir>
    python3 report_mustfix.py <scan-dir> --min-severity high
    python3 report_mustfix.py <scan-dir> --include-dismissed
"""
import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def load_findings(scan_dir):
    p = Path(scan_dir)
    for name in ["deduplicated-findings.json", "normalized-findings.json"]:
        f = p / name
        if f.exists():
            return json.loads(f.read_text())
    return []


def load_metadata(scan_dir):
    f = Path(scan_dir) / "scan-metadata.json"
    if f.exists():
        return json.loads(f.read_text())
    return {}


def shorten_path(filepath, repo_name=""):
    parts = filepath.replace("\\", "/").split("/")
    if repo_name:
        short = repo_name.split("/")[-1]
        for i, p in enumerate(parts):
            if p == short:
                return "/".join(parts[i + 1:])
    for i, p in enumerate(parts):
        if p in ("repo", "repos"):
            return "/".join(parts[i + 1:]) if i + 1 < len(parts) else filepath
    return filepath


SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
EFFORT_ESTIMATE = {
    "secrets": "Small (rotate credential, remove from code)",
    "sca": "Small (update dependency version)",
    "k8s": "Small (add security context fields)",
    "config": "Small (configuration change)",
    "cicd": "Medium (pin actions, sanitize expressions)",
    "injection": "Medium (add input validation/escaping)",
    "other": "Variable (requires code review)",
}


def _group_findings(findings, repo_short, min_severity="high"):
    min_rank = SEV_RANK.get(min_severity, 3)
    filtered = [f for f in findings if SEV_RANK.get(f["severity"], 0) >= min_rank]

    groups = defaultdict(list)
    for f in filtered:
        key = (f.get("rule_id", "") or f.get("title", ""), f.get("category", "other"))
        groups[key].append(f)

    fixes = []
    for (rule_id, category), group in groups.items():
        max_sev = max(group, key=lambda f: SEV_RANK.get(f["severity"], 0))["severity"]
        files = []
        for f in group:
            fpath = shorten_path(f.get("file", ""), repo_short)
            line = f.get("line_start", "")
            files.append(f"{fpath}:{line}" if line else fpath)

        title = group[0].get("title", rule_id)
        description = group[0].get("description", "")
        recommendation = group[0].get("recommendation", "")
        sources = sorted(set(s for f in group for s in f.get("detected_by", [f.get("source", "")])))

        fixes.append({
            "title": title,
            "severity": max_sev,
            "category": category,
            "files": files,
            "file_count": len(files),
            "description": description[:500],
            "recommendation": recommendation,
            "detected_by": sources,
            "effort": EFFORT_ESTIMATE.get(category, "Variable"),
        })

    fixes.sort(key=lambda f: (-SEV_RANK.get(f["severity"], 0), -f["file_count"]))
    return fixes


def _group_dismissed(findings, repo_short, min_severity="high"):
    min_rank = SEV_RANK.get(min_severity, 3)
    dismissed = [f for f in findings if SEV_RANK.get(f["severity"], 0) < min_rank]

    by_tool = defaultdict(int)
    for f in dismissed:
        by_tool[f.get("source", "unknown")] += 1

    return by_tool, len(dismissed)


def generate_mustfix(findings, metadata, min_severity="high", include_dismissed=True):
    lines = []
    repo = metadata.get("repo", "Unknown")
    repo_short = repo.split("/")[-1] if "/" in repo else repo
    date = metadata.get("date", "Unknown")
    branch = metadata.get("branch", "main")
    commit = metadata.get("commit", "unknown")[:8]
    tools = metadata.get("tools_run", [])
    ai_skills = metadata.get("ai_skills_run", [])

    sev_counts = Counter(f["severity"] for f in findings)

    # Header
    lines.append(f"# {repo_short}: Must-Fix Security Items ({min_severity.upper()}+)")
    lines.append("")
    lines.append(f"**Scope:** {min_severity.upper()} severity and above  ")
    lines.append(f"**Repository:** {repo} ({branch})  ")
    lines.append(f"**Scan date:** {date}  ")
    lines.append(f"**Commit:** {commit}  ")
    if tools:
        lines.append(f"**Tools:** {', '.join(tools)}  ")
    if ai_skills:
        lines.append(f"**AI Skills:** {', '.join(ai_skills)}  ")
    lines.append("")

    # Group findings into fixes
    fixes = _group_findings(findings, repo_short, min_severity)

    if not fixes:
        lines.append("No must-fix items found at this severity threshold.")
        lines.append("")
        return "\n".join(lines)

    # Generate Fix N sections
    for i, fix in enumerate(fixes, 1):
        sev_label = fix["severity"].upper()
        lines.append(f"## Fix {i}: {fix['title']} ({sev_label})")
        lines.append("")

        lines.append(f"**Risk:** {fix['description']}")
        lines.append("")

        lines.append(f"**Files to change ({fix['file_count']} instance{'s' if fix['file_count'] != 1 else ''}):**")
        for fpath in fix["files"][:10]:
            lines.append(f"- `{fpath}`")
        if len(fix["files"]) > 10:
            lines.append(f"- +{len(fix['files']) - 10} more")
        lines.append("")

        lines.append(f"**Detected by:** {', '.join(fix['detected_by'])}")
        lines.append("")

        if fix["recommendation"]:
            lines.append(f"**Fix:** {fix['recommendation']}")
            lines.append("")

        lines.append(f"**Effort:** {fix['effort']}")
        lines.append("")

    # Dismissed findings
    if include_dismissed:
        dismissed_by_tool, dismissed_count = _group_dismissed(findings, repo_short, min_severity)
        if dismissed_count > 0:
            lines.append("## Dismissed Findings")
            lines.append("")
            lines.append(f"{dismissed_count} findings below {min_severity.upper()} severity were not included:")
            lines.append("")
            for tool, count in sorted(dismissed_by_tool.items(), key=lambda x: -x[1]):
                lines.append(f"- **{tool}:** {count} findings (below threshold)")
            lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| # | Finding | Severity | Files | Effort |")
    lines.append("|---|---------|----------|-------|--------|")
    for i, fix in enumerate(fixes, 1):
        title = fix["title"][:50]
        lines.append(f"| {i} | {title} | {fix['severity'].upper()} | {fix['file_count']} | {fix['effort'].split('(')[0].strip()} |")
    lines.append("")

    lines.append(f"**Recommended fix order:** " + " then ".join(
        f"Fix {i+1}" for i in range(min(len(fixes), 10))
    ))
    lines.append("")
    lines.append(f"**Total:** {len(fixes)} must-fix items, {sum(f['file_count'] for f in fixes)} file locations.")
    lines.append("")
    lines.append("---")
    lines.append("*Generated by RHOAI Security Audit*")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_dir")
    parser.add_argument("--min-severity", default="high", choices=["critical", "high", "medium", "low"])
    parser.add_argument("--include-dismissed", action="store_true", default=True)
    parser.add_argument("--no-dismissed", action="store_true")
    args = parser.parse_args()

    findings = load_findings(args.scan_dir)
    metadata = load_metadata(args.scan_dir)
    include_dismissed = not args.no_dismissed
    print(generate_mustfix(findings, metadata, args.min_severity, include_dismissed))


if __name__ == "__main__":
    main()
