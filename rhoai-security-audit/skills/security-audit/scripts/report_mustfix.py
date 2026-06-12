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

from report_common import (
    load_findings, load_metadata, shorten_path, github_url as _github_url_full,
    parse_ai_findings as load_ai_findings, SEV_COLORS, SOURCE_COLORS,
    TRIAGE_BADGES_HTML as TRIAGE_BADGES,
)


def _github_url(filepath, line_start, repo_full, ref):
    return _github_url_full(filepath, line_start, None, repo_full, ref)


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
    lines.append("> **CONFIDENTIAL** — This report may contain undisclosed security findings. Do not share outside authorized personnel. Do not post in public channels.")
    lines.append("")
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
MUSTFIX_HTML_STYLE = """
* { margin:0; padding:0; box-sizing:border-box; }
body { font:14px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#0d1117; color:#c9d1d9; padding:24px 40px; max-width:1100px; margin:0 auto; }
a { color:#58a6ff; text-decoration:none; }
a:hover { text-decoration:underline; }
h1 { font-size:20px; color:#f0f6fc; margin-bottom:2px; }
h2 { font-size:16px; margin:24px 0 12px; color:#f0f6fc; padding-bottom:8px; border-bottom:1px solid #30363d; }
.header-meta { color:#4a5568; font-size:12px; margin-bottom:16px; }
.stat-row { display:flex; gap:10px; margin:12px 0; flex-wrap:wrap; }
.stat-card { background:#161b22; border:1px solid #30363d; border-radius:6px; padding:10px 16px; text-align:center; }
.stat-count { font-size:24px; font-weight:700; }
.stat-label { font-size:10px; text-transform:uppercase; color:#8b949e; }
.finding-card { background:#161b22; border:1px solid #30363d; border-left:3px solid #6c757d; border-radius:6px; padding:12px 14px; margin-bottom:8px; transition:border-color .15s; }
.finding-card:hover { border-color:#58a6ff; }
.card-header { display:flex; align-items:center; gap:6px; flex-wrap:wrap; margin-bottom:4px; }
.card-title { color:#f0f6fc; font-size:13px; font-weight:500; }
.card-file { margin-left:auto; font-size:11px; }
.file-link { color:#58a6ff; font-size:11px; }
.card-desc { font-size:12px; color:#c9d1d9; margin-top:4px; }
.chip { display:inline-block; padding:1px 7px; border-radius:10px; font-size:10px; font-weight:600; color:#fff; white-space:nowrap; }
.snippet { background:#0d1117; border:1px solid #21262d; padding:6px 8px; border-radius:4px; font-size:11px; margin-top:6px; overflow-x:auto; color:#e6edf3; }
.card-expand { padding:8px 0 4px; border-top:1px solid #21262d; margin-top:8px; font-size:12px; }
.fix-label { color:#8b949e; font-weight:600; font-size:11px; text-transform:uppercase; }
.card-toggle { color:#58a6ff; font-size:11px; cursor:pointer; margin-top:4px; }
.card-toggle:hover { text-decoration:underline; }
table { width:100%; border-collapse:collapse; font-size:12px; }
th { background:#0d1117; padding:6px 8px; text-align:left; border-bottom:1px solid #30363d; color:#8b949e; font-weight:600; text-transform:uppercase; font-size:10px; }
td { padding:5px 8px; border-bottom:1px solid #161b22; }
tr:hover { background:#0d1117; }
.footer { margin-top:32px; padding-top:12px; border-top:1px solid #21262d; color:#4a5568; font-size:11px; }
"""


def _mustfix_file_display(filepath, line_start):
    parts = filepath.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p in ("repo", "repos"):
            filepath = "/".join(parts[i + 2:]) if i + 2 < len(parts) else filepath
            break
    return f"{filepath}:{line_start}" if line_start else filepath


def _render_mustfix_card(f, repo_full, ref, card_idx):
    from html import escape as esc
    sev = f.get("severity", "info")
    color = SEV_COLORS.get(sev, "#6c757d")
    fpath = f.get("file", "")
    line = f.get("line_start", 0)
    line_end = f.get("line_end", 0)
    url = _github_url(fpath, line, repo_full, ref)
    display = _mustfix_file_display(fpath, line)
    source = f.get("source", "")
    triage_status = f.get("triage", {}).get("status", "") if isinstance(f.get("triage"), dict) else f.get("triage", "")
    title_text = esc(f.get("title", "")[:100])
    raw_desc = f.get("description", "")
    snippet = f.get("snippet", "")
    rec = f.get("recommendation", "")

    if not rec and "Remediation:" in raw_desc:
        parts = raw_desc.split("Remediation:", 1)
        raw_desc = parts[0].strip()
        rec = parts[1].strip()

    desc = esc(raw_desc[:800])
    rec = esc(rec[:800])

    triage_badge = TRIAGE_BADGES.get(triage_status, "")

    confidence = f.get("confidence", 0)
    conf_badge = ""
    if f.get("origin") == "ai" and confidence:
        conf_val = float(confidence)
        if conf_val >= 0.8:
            conf_badge = '<span class="chip" style="background:#166534;font-size:9px" title="Code-verified, multi-agent confirmed">HIGH conf</span>'
        elif conf_val >= 0.6:
            conf_badge = '<span class="chip" style="background:#854d0e;font-size:9px" title="Plausible but not fully verified">MED conf</span>'
        else:
            conf_badge = '<span class="chip" style="background:#991b1b;font-size:9px" title="Speculative or challenged">LOW conf</span>'

    sev_badge = f'<span class="chip" style="background:{color};color:#fff">{sev.upper()}</span>{triage_badge}{conf_badge}'

    src_badge = ""
    if source:
        src_color = SOURCE_COLORS.get(source, "#30363d")
        src_text_color = "#fff" if src_color != "#30363d" else "#8b949e"
        src_badge = f'<span class="chip" style="background:{src_color};color:{src_text_color}">{esc(source)}</span>'

    file_link = f'<a href="{esc(url) if url else ""}" class="file-link" target="_blank">{esc(display)} ↗</a>' if url else f'<code>{esc(display)}</code>'

    snippet_html = ""
    if snippet:
        lines = snippet.strip().split("\n")
        if len(lines) > 6:
            lines = lines[:6] + ["..."]
        snippet_html = f'<pre class="snippet"><code>{esc(chr(10).join(lines))}</code></pre>'

    expand_id = f"mustfix-expand-{card_idx}"
    rec_html = ""
    if rec:
        rec_html = f'''<div class="card-expand" id="{expand_id}" style="display:none">
            <div class="card-fix"><span class="fix-label">Fix:</span> {rec}</div>
        </div>
        <div class="card-toggle" onclick="var e=document.getElementById('{expand_id}');e.style.display=e.style.display==='none'?'block':'none';this.textContent=e.style.display==='none'?'Show fix ▾':'Hide fix ▴'">Show fix ▾</div>'''

    return f'''<div class="finding-card" style="border-left-color:{color}">
    <div class="card-header">
        {sev_badge}
        <span class="card-title">{title_text}</span>
        {src_badge}
        <span class="card-file">{file_link}</span>
    </div>
    <div class="card-desc">{desc}</div>
    {snippet_html}
    {rec_html}
</div>'''


def generate_mustfix_html(findings, ai_findings, metadata, min_severity="high"):
    from html import escape
    repo_full = metadata.get("repo", "Unknown")
    repo_short = repo_full.split("/")[-1] if "/" in repo_full else repo_full

    all_combined = findings + ai_findings
    min_rank = SEV_RANK.get(min_severity, 3)
    must_fix = [f for f in all_combined if SEV_RANK.get(f.get("severity", ""), 0) >= min_rank]
    must_fix.sort(key=lambda f: (-SEV_RANK.get(f.get("severity", ""), 0), f.get("file", "")))

    if not must_fix:
        return f"<html><body style='background:#0d1117;color:#c9d1d9;padding:40px'><h1>No must-fix items at {min_severity.upper()}+ severity</h1></body></html>"

    branch = metadata.get("branch", "main")
    commit = metadata.get("commit", "")
    ref = commit or branch
    date = metadata.get("date", "")

    from collections import Counter as Ctr
    sev_counts = Ctr(f["severity"] for f in must_fix)
    triage_counts = Ctr(
        f.get("triage", {}).get("status", "sast-only") if isinstance(f.get("triage"), dict) else "sast-only"
        for f in must_fix)

    stat_cards = ""
    for sev in ["critical", "high", "medium"]:
        c = sev_counts.get(sev, 0)
        if c:
            stat_cards += f'<div class="stat-card" style="border-left:3px solid {SEV_COLORS[sev]}"><div class="stat-count" style="color:{SEV_COLORS[sev]}">{c}</div><div class="stat-label">{sev.title()}</div></div>'

    cards_html = "\n".join(_render_mustfix_card(f, repo_full, ref, i) for i, f in enumerate(must_fix))

    summary_rows = []
    for i, f in enumerate(must_fix, 1):
        sev = f["severity"]
        sev_chip = f'<span class="chip" style="background:{SEV_COLORS.get(sev,"#6c757d")};color:#fff;font-size:10px">{sev.upper()}</span>'
        src = f.get("source", "")
        title = escape(f.get("title", "")[:50])
        summary_rows.append(f"<tr><td>{i}</td><td>{title}</td><td>{sev_chip}</td><td>{escape(src)}</td></tr>")

    corr = triage_counts.get("corroborated", 0)
    ai_only = triage_counts.get("ai-only", 0)
    sast_only = triage_counts.get("sast-only", 0)

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Must-Fix: {escape(repo_short)}</title>
<style>{MUSTFIX_HTML_STYLE}</style></head><body>
<div style="background:#dc354520;border:1px solid #dc3545;border-radius:6px;padding:10px 14px;margin-bottom:16px;font-size:12px;color:#f0f6fc">
    <strong style="color:#dc3545">CONFIDENTIAL</strong> — This report may contain undisclosed security findings. Do not share outside authorized personnel. Do not post in public channels.
</div>
<h1>Must-Fix: {escape(repo_short)}</h1>
<div class="header-meta">{escape(repo_full)} | {escape(branch)} | {escape(str(commit)[:8])} | {escape(str(date)[:10])} | {min_severity.upper()}+ severity</div>

<div class="stat-row">{stat_cards}</div>

<div style="display:flex;gap:16px;flex-wrap:wrap;font-size:11px;color:#8b949e;margin:8px 0 4px;padding:6px 0;border-bottom:1px solid #21262d">
    <span><span class="chip" style="background:#16a34a">CORR</span> Corroborated: found by both SAST tools and AI review</span>
    <span><span class="chip" style="background:#2563eb">AI</span> AI-only: logic/semantic issue found by AI review only</span>
    <span style="color:#4a5568">No badge = SAST tool finding only</span>
</div>

<p style="color:#8b949e;font-size:12px;margin-bottom:12px">{len(must_fix)} must-fix findings: {corr} corroborated, {ai_only} AI-only, {sast_only} SAST-only</p>

{cards_html}

<h2>Summary</h2>
<table>
<thead><tr><th>#</th><th>Finding</th><th>Severity</th><th>Source</th></tr></thead>
<tbody>{''.join(summary_rows)}</tbody>
</table>

<p style="color:#8b949e;margin-top:16px"><strong>Total:</strong> {len(must_fix)} must-fix items</p>
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
    # Only load AI findings from raw markdown if triaged data lacks them
    has_ai = any(f.get("origin") == "ai" for f in findings)
    ai_findings = load_ai_findings(args.scan_dir) if not has_ai else []
    metadata = load_metadata(args.scan_dir)

    if args.html:
        print(generate_mustfix_html(findings, ai_findings, metadata, args.min_severity))
    else:
        all_combined = findings + ai_findings
        include_dismissed = not args.no_dismissed
        print(generate_mustfix(all_combined, metadata, args.min_severity, include_dismissed))


if __name__ == "__main__":
    main()
