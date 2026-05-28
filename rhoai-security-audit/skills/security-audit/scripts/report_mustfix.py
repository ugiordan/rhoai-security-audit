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
    triaged = p / "triaged-findings.json"
    if triaged.exists():
        return json.loads(triaged.read_text())
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


def load_ai_findings(scan_dir):
    """Load AI review findings from raw/adversarial-reviewing/ and raw/semantic-scan/."""
    import re as _re
    p = Path(scan_dir)
    ai_findings = []
    for subdir in ["raw/adversarial-reviewing", "raw/semantic-scan"]:
        d = p / subdir
        if not d.exists():
            continue
        source = "adversarial-review" if "adversarial" in subdir else "semantic-scan"
        for md_file in sorted(d.glob("*.md")):
            if md_file.name.startswith("."):
                continue
            text = md_file.read_text()
            blocks = _re.split(r'\n(?=(?:Finding ID:|###?\s+(?:SEC|PERF|QUAL|CORR|ARCH|FINDING)-\d+))', text)
            for block in blocks:
                id_match = _re.search(r'(?:Finding ID:\s*|###?\s+)((?:SEC|PERF|QUAL|CORR|ARCH|FINDING)-\d+)', block)
                if not id_match:
                    continue
                f = {"id": id_match.group(1), "source": source, "category": "ai-review", "detected_by": [source]}
                sev_match = _re.search(r'Severity:\s*(\w+)', block, _re.IGNORECASE)
                if sev_match:
                    sev = sev_match.group(1).lower()
                    f["severity"] = {"critical": "critical", "important": "high", "high": "high",
                                     "medium": "medium", "minor": "low"}.get(sev, "medium")
                else:
                    f["severity"] = "medium"
                title_match = _re.search(r'Title:\s*(.+?)(?:\n|$)', block)
                f["title"] = title_match.group(1).strip() if title_match else f["id"]
                f["rule_id"] = f["id"]
                file_match = _re.search(r'File:\s*`?([^\n`]+)`?', block)
                f["file"] = file_match.group(1).strip() if file_match else ""
                line_match = _re.search(r'Lines?:\s*(\d+)', block)
                f["line_start"] = int(line_match.group(1)) if line_match else 0
                evidence_match = _re.search(r'Evidence:\s*(.+?)(?=\n(?:Impact|Recommended|Finding ID:|\Z))', block, _re.DOTALL)
                f["description"] = evidence_match.group(1).strip()[:500] if evidence_match else ""
                fix_match = _re.search(r'Recommended fix:\s*(.+?)(?=\n(?:Finding ID:|\Z))', block, _re.DOTALL)
                f["recommendation"] = fix_match.group(1).strip()[:300] if fix_match else ""
                ai_findings.append(f)
    return ai_findings


MUSTFIX_HTML_STYLE = """
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font: 14px/1.6 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; max-width: 1000px; margin: 0 auto; padding: 32px 40px; }
h1 { font-size: 24px; margin-bottom: 8px; color: #f0f6fc; }
h2 { font-size: 18px; margin: 28px 0 12px; color: #f0f6fc; padding-bottom: 8px; border-bottom: 1px solid #30363d; }
.meta { color: #8b949e; font-size: 13px; margin-bottom: 24px; }
.fix-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 20px; margin: 12px 0; }
.fix-header { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
.fix-title { font-size: 15px; font-weight: 600; color: #f0f6fc; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; color: #fff; }
.badge-critical { background: #dc3545; }
.badge-high { background: #fd7e14; }
.badge-medium { background: #ffc107; color: #000; }
.badge-source { background: #30363d; color: #8b949e; font-weight: 400; }
.fix-body { font-size: 13px; color: #c9d1d9; }
.fix-body p { margin: 6px 0; }
.fix-body code { background: #21262d; padding: 2px 6px; border-radius: 3px; font-size: 12px; }
.fix-body ul { padding-left: 20px; margin: 4px 0; }
.fix-body .label { color: #8b949e; font-weight: 600; text-transform: uppercase; font-size: 11px; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 13px; }
th { background: #161b22; padding: 8px 10px; text-align: left; border-bottom: 2px solid #30363d; color: #8b949e; font-weight: 600; text-transform: uppercase; font-size: 11px; }
td { padding: 6px 10px; border-bottom: 1px solid #21262d; }
tr:hover { background: #161b22; }
.footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #30363d; color: #8b949e; font-size: 12px; }
"""


def generate_mustfix_html(findings, ai_findings, metadata, min_severity="high"):
    from html import escape
    repo = metadata.get("repo", "Unknown")
    repo_short = repo.split("/")[-1] if "/" in repo else repo

    all_combined = findings + ai_findings
    fixes = _group_findings(all_combined, repo_short, min_severity)

    if not fixes:
        return f"<html><body style='background:#0d1117;color:#c9d1d9;padding:40px'><h1>No must-fix items at {min_severity.upper()}+ severity</h1></body></html>"

    sev_badge = lambda s: f'<span class="badge badge-{s}">{s.upper()}</span>'

    cards = []
    for i, fix in enumerate(fixes, 1):
        files_html = "".join(f"<li><code>{escape(f)}</code></li>" for f in fix["files"][:10])
        if len(fix["files"]) > 10:
            files_html += f"<li>+{len(fix['files'])-10} more</li>"
        source_badges = " ".join(f'<span class="badge badge-source">{escape(s)}</span>' for s in fix["detected_by"])
        rec = escape(fix.get("recommendation", "")) if fix.get("recommendation") else ""
        rec_html = f'<p><span class="label">Fix:</span> {rec}</p>' if rec else ""

        cards.append(f"""
        <div class="fix-card" style="border-left: 4px solid {'#dc3545' if fix['severity']=='critical' else '#fd7e14' if fix['severity']=='high' else '#ffc107'}">
            <div class="fix-header">
                <span style="color:#8b949e;font-weight:600">Fix {i}</span>
                {sev_badge(fix['severity'])}
                {source_badges}
            </div>
            <div class="fix-title">{escape(fix['title'])}</div>
            <div class="fix-body">
                <p>{escape(fix['description'][:300])}</p>
                <p><span class="label">Files ({fix['file_count']}):</span></p>
                <ul>{files_html}</ul>
                {rec_html}
                <p><span class="label">Effort:</span> {escape(fix['effort'])}</p>
            </div>
        </div>""")

    summary_rows = []
    for i, fix in enumerate(fixes, 1):
        summary_rows.append(f"<tr><td>{i}</td><td>{escape(fix['title'][:50])}</td>"
                            f"<td>{sev_badge(fix['severity'])}</td>"
                            f"<td>{fix['file_count']}</td>"
                            f"<td>{escape(fix['effort'].split('(')[0].strip())}</td></tr>")

    sast_count = len([f for f in fixes if any(s not in ("adversarial-review", "semantic-scan") for s in f["detected_by"])])
    ai_count = len([f for f in fixes if any(s in ("adversarial-review", "semantic-scan") for s in f["detected_by"])])

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Must-Fix: {escape(repo_short)}</title>
<style>{MUSTFIX_HTML_STYLE}</style></head><body>
<h1>Must-Fix: {escape(repo_short)}</h1>
<div class="meta">
    {escape(repo)} | Branch: {escape(metadata.get('branch','main'))} |
    {escape(str(metadata.get('date','')))} |
    {len(fixes)} items ({sast_count} SAST, {ai_count} AI review)
</div>

{''.join(cards)}

<h2>Summary</h2>
<table>
<thead><tr><th>#</th><th>Finding</th><th>Severity</th><th>Files</th><th>Effort</th></tr></thead>
<tbody>{''.join(summary_rows)}</tbody>
</table>

<p style="color:#8b949e;margin-top:16px"><strong>Total:</strong> {len(fixes)} must-fix items, {sum(f['file_count'] for f in fixes)} file locations</p>
<div class="footer">Generated by RHOAI Security Audit</div>
</body></html>"""


EFFORT_ESTIMATE["ai-review"] = "Variable (requires code review and architectural understanding)"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_dir")
    parser.add_argument("--min-severity", default="high", choices=["critical", "high", "medium", "low"])
    parser.add_argument("--include-dismissed", action="store_true", default=True)
    parser.add_argument("--no-dismissed", action="store_true")
    parser.add_argument("--html", action="store_true", help="Generate HTML output instead of markdown")
    args = parser.parse_args()

    findings = load_findings(args.scan_dir)
    ai_findings = load_ai_findings(args.scan_dir)
    metadata = load_metadata(args.scan_dir)

    if args.html:
        print(generate_mustfix_html(findings, ai_findings, metadata, args.min_severity))
    else:
        all_combined = findings + ai_findings
        include_dismissed = not args.no_dismissed
        print(generate_mustfix(all_combined, metadata, args.min_severity, include_dismissed))


if __name__ == "__main__":
    main()
