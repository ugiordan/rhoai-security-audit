#!/usr/bin/env python3
"""Generate self-contained HTML security report.

Styled like architecture-analyzer pages with:
- Severity donut chart (CSS-only)
- Collapsible finding sections
- Tool coverage heatmap
- Color-coded severity badges
- Dark sidebar navigation

Usage:
    python3 report_html.py <scan-dir> > report.html
    python3 report_html.py <scan-dir1> <scan-dir2> > multi-report.html
"""
import argparse
import json
from collections import Counter, defaultdict
from html import escape
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


def load_ai_findings(scan_dir):
    """Load AI review findings from raw/adversarial-reviewing/ and raw/semantic-scan/."""
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
            findings = _parse_ai_findings(text, source, md_file.name)
            ai_findings.extend(findings)
    return ai_findings


def _parse_ai_findings(text, source, filename):
    """Extract structured findings from AI review markdown."""
    import re
    findings = []
    blocks = re.split(r'\n(?=(?:Finding ID:|###?\s+(?:SEC|PERF|QUAL|CORR|ARCH|FINDING)-\d+))', text)
    for block in blocks:
        finding = {}
        id_match = re.search(r'(?:Finding ID:\s*|###?\s+)((?:SEC|PERF|QUAL|CORR|ARCH|FINDING)-\d+)', block)
        if not id_match:
            continue
        finding["id"] = id_match.group(1)
        finding["source"] = source

        sev_match = re.search(r'Severity:\s*(\w+)', block, re.IGNORECASE)
        if sev_match:
            sev = sev_match.group(1).lower()
            sev_map = {"critical": "critical", "important": "high", "high": "high",
                       "medium": "medium", "minor": "low", "low": "low"}
            finding["severity"] = sev_map.get(sev, "medium")
        else:
            finding["severity"] = "medium"

        conf_match = re.search(r'Confidence:\s*(\w+)', block, re.IGNORECASE)
        finding["confidence"] = conf_match.group(1).lower() if conf_match else "medium"

        title_match = re.search(r'Title:\s*(.+?)(?:\n|$)', block)
        finding["title"] = title_match.group(1).strip() if title_match else finding["id"]

        file_match = re.search(r'File:\s*`?([^\n`]+)`?', block)
        finding["file"] = file_match.group(1).strip() if file_match else ""

        line_match = re.search(r'Lines?:\s*(\d+)', block)
        finding["line_start"] = int(line_match.group(1)) if line_match else 0

        evidence_match = re.search(r'Evidence:\s*(.+?)(?=\n(?:Impact|Recommended|Finding ID:|\Z))', block, re.DOTALL)
        finding["description"] = evidence_match.group(1).strip()[:500] if evidence_match else ""

        fix_match = re.search(r'Recommended fix:\s*(.+?)(?=\n(?:Finding ID:|\Z))', block, re.DOTALL)
        finding["recommendation"] = fix_match.group(1).strip()[:300] if fix_match else ""

        finding["category"] = "ai-review"
        finding["detected_by"] = [source]
        findings.append(finding)
    return findings


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


SEV_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#17a2b8",
    "info": "#6c757d",
}

CAT_LABELS = {
    "secrets": "Secrets",
    "sca": "CVEs / SCA",
    "k8s": "Kubernetes",
    "config": "Configuration",
    "cicd": "CI/CD",
    "injection": "Injection",
    "other": "SAST",
}


def _sev_badge(sev):
    color = SEV_COLORS.get(sev, "#6c757d")
    return f'<span class="badge" style="background:{color}">{escape(sev.upper())}</span>'


def _github_link(filepath, line_start, line_end, repo_full="", branch="main"):
    """Build a GitHub permalink for a finding's source location."""
    clean = shorten_path(filepath, repo_full.split("/")[-1] if repo_full else "")
    if not repo_full or not clean:
        return f"<code>{escape(clean or filepath)}</code>"
    frag = f"#L{line_start}" if line_start else ""
    if line_end and line_end != line_start and line_start:
        frag = f"#L{line_start}-L{line_end}"
    url = f"https://github.com/{repo_full}/blob/{branch}/{clean}{frag}"
    return f'<a href="{url}" style="color:#58a6ff"><code>{escape(clean)}</code></a>'


def _snippet_block(snippet):
    """Render a code snippet in a collapsible pre block."""
    if not snippet:
        return ""
    lines = snippet.strip().split("\n")
    if len(lines) > 8:
        lines = lines[:8] + ["..."]
    code = escape("\n".join(lines))
    return f'<pre style="background:#161b22;padding:8px;border-radius:4px;font-size:11px;margin:4px 0;overflow-x:auto;max-width:500px"><code>{code}</code></pre>'


def _render_findings_table(findings, repo_short, show_detected_by=True, repo_full="", branch="main"):
    if not findings:
        return "<p>No findings.</p>"
    rows = []
    for i, f in enumerate(findings[:100], 1):
        fpath = f.get("file", "")
        line = f.get("line_start", 0)
        line_end = f.get("line_end", 0)
        file_link = _github_link(fpath, line, line_end, repo_full, branch)
        ftitle = escape(f.get("title", "")[:80])
        src = escape(f.get("source", ""))
        det = ", ".join(f.get("detected_by", [src]))
        rec = escape(f.get("recommendation", "")[:100])
        sev = _sev_badge(f["severity"])
        snippet = _snippet_block(f.get("snippet", ""))
        det_col = f"<td>{escape(det)}</td>" if show_detected_by else ""
        line_display = f"{line}" if line else ""
        rows.append(f"<tr><td>{i}</td><td>{sev}</td><td>{src}</td>"
                     f"<td>{file_link}</td><td>{line_display}</td>"
                     f"<td>{ftitle}{snippet}</td>{det_col}"
                     f"<td>{rec}</td></tr>")
    overflow = ""
    if len(findings) > 100:
        overflow = f"<p class='overflow'>+{len(findings) - 100} more findings not shown</p>"
    det_header = "<th>Detected By</th>" if show_detected_by else ""
    return f"""<table>
<thead><tr><th>#</th><th>Severity</th><th>Tool</th><th>File</th><th>Line</th><th>Title</th>{det_header}<th>Recommendation</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>{overflow}"""


def generate_html(scan_dirs):
    all_data = []
    for d in scan_dirs:
        findings = load_findings(d)
        metadata = load_metadata(d)
        if findings or metadata:
            all_data.append((d, findings, metadata))

    if not all_data:
        return "<html><body><h1>No scan data found.</h1></body></html>"

    multi = len(all_data) > 1
    all_findings = []
    for _, f, _ in all_data:
        all_findings.extend(f)

    # AI findings are included in triaged-findings.json (origin=ai)
    # If not triaged yet, load them separately as fallback
    ai_findings = [f for f in all_findings if f.get("origin") == "ai"]
    if not ai_findings:
        for d in scan_dirs:
            ai_findings.extend(load_ai_findings(d))

    first_meta = all_data[0][2]
    title = "RHOAI Security Audit Report" if multi else f"Security Report: {first_meta.get('repo', 'Unknown')}"

    combined = all_findings + ai_findings
    sev_counts = Counter(f["severity"] for f in combined)
    tool_counts = Counter(f.get("source", "unknown") for f in combined)
    cat_counts = Counter(f.get("category", "other") for f in combined)
    total = len(combined)

    # Severity donut data
    donut_segments = []
    offset = 0
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = sev_counts.get(sev, 0)
        if count == 0:
            continue
        pct = (count / max(total, 1)) * 100
        color = SEV_COLORS[sev]
        donut_segments.append(f"{color} {offset}% {offset + pct}%")
        offset += pct

    donut_gradient = ", ".join(donut_segments) if donut_segments else "#eee 0% 100%"

    # Sidebar nav items
    nav_items = []
    nav_items.append('<a href="#summary">Summary</a>')
    nav_items.append('<a href="#tools">Tool Coverage</a>')
    if any(f.get("category") == "sca" for f in all_findings):
        nav_items.append('<a href="#cves">CVEs</a>')
    if any(f.get("category") == "secrets" for f in all_findings):
        nav_items.append('<a href="#secrets">Secrets</a>')
    if ai_findings:
        nav_items.append('<a href="#ai-review">AI Review</a>')
    nav_items.append('<a href="#critical">Critical</a>')
    nav_items.append('<a href="#high">High</a>')
    if multi:
        for _, _, m in all_data:
            repo = m.get("repo", "?").split("/")[-1]
            nav_items.append(f'<a href="#repo-{escape(repo)}">{escape(repo)}</a>')

    # Tool x severity matrix
    tool_sev = defaultdict(Counter)
    for f in all_findings:
        tool_sev[f.get("source", "unknown")][f["severity"]] += 1

    tool_rows = []
    for tool in sorted(tool_sev.keys()):
        s = tool_sev[tool]
        t = sum(s.values())
        cells = "".join(
            f'<td class="sev-{sev}">{s.get(sev,0) or ""}</td>'
            for sev in ["critical", "high", "medium", "low", "info"]
        )
        tool_rows.append(f"<tr><td><strong>{escape(tool)}</strong></td>{cells}<td><strong>{t}</strong></td></tr>")

    # Category summary
    cat_rows = []
    for cat, count in cat_counts.most_common():
        label = CAT_LABELS.get(cat, cat)
        cat_rows.append(f"<tr><td>{escape(label)}</td><td>{count}</td></tr>")

    # Metadata
    meta_html = ""
    if not multi:
        m = first_meta
        meta_html = f"""
        <div class="meta-grid">
            <div class="meta-item"><span class="meta-label">Repository</span><span class="meta-value">{escape(m.get('repo',''))}</span></div>
            <div class="meta-item"><span class="meta-label">Branch</span><span class="meta-value">{escape(m.get('branch','main'))}</span></div>
            <div class="meta-item"><span class="meta-label">Commit</span><span class="meta-value"><code>{escape(str(m.get('commit',''))[:8])}</code></span></div>
            <div class="meta-item"><span class="meta-label">Date</span><span class="meta-value">{escape(str(m.get('date','')))}</span></div>
            <div class="meta-item"><span class="meta-label">Tools</span><span class="meta-value">{len(tool_counts)}</span></div>
            <div class="meta-item"><span class="meta-label">Total Findings</span><span class="meta-value">{total}</span></div>
        </div>"""
    else:
        meta_html = f"""
        <div class="meta-grid">
            <div class="meta-item"><span class="meta-label">Repos Scanned</span><span class="meta-value">{len(all_data)}</span></div>
            <div class="meta-item"><span class="meta-label">Date</span><span class="meta-value">{escape(str(first_meta.get('date','')))}</span></div>
            <div class="meta-item"><span class="meta-label">Tools</span><span class="meta-value">{len(tool_counts)}</span></div>
            <div class="meta-item"><span class="meta-label">Total Findings</span><span class="meta-value">{total}</span></div>
        </div>"""

    # Severity stat cards
    stat_cards = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        c = sev_counts.get(sev, 0)
        color = SEV_COLORS[sev]
        stat_cards += f'<div class="stat-card" style="border-left: 4px solid {color}"><div class="stat-count">{c}</div><div class="stat-label">{sev.title()}</div></div>'

    # Finding sections
    repo_short = first_meta.get("repo", "").split("/")[-1] if not multi else ""
    repo_full = first_meta.get("repo", "") if not multi else ""
    branch = first_meta.get("branch", "main")

    sca_section = ""
    sca_findings = [f for f in all_findings if f.get("category") == "sca"]
    if sca_findings:
        sca_section = f"""
        <section id="cves">
            <h2>Dependency Vulnerabilities ({len(sca_findings)})</h2>
            {_render_findings_table(sca_findings, repo_short, repo_full=repo_full, branch=branch)}
        </section>"""

    secrets_section = ""
    secret_findings = [f for f in all_findings if f.get("category") == "secrets"]
    if secret_findings:
        secrets_section = f"""
        <section id="secrets">
            <h2>Secrets Detected ({len(secret_findings)})</h2>
            {_render_findings_table(secret_findings, repo_short, show_detected_by=False, repo_full=repo_full, branch=branch)}
        </section>"""

    # AI Review section
    ai_section = ""
    if ai_findings:
        ai_important = [f for f in ai_findings if f["severity"] in ("critical", "high")]
        ai_minor = [f for f in ai_findings if f["severity"] not in ("critical", "high")]
        ai_rows = []
        for i, f in enumerate(ai_findings, 1):
            file_link = _github_link(f.get("file", ""), f.get("line_start", 0),
                                     f.get("line_end", 0), repo_full, branch)
            sev = _sev_badge(f["severity"])
            ftitle = escape(f.get("title", "")[:80])
            snippet = _snippet_block(f.get("snippet", ""))
            desc = escape(f.get("description", "")[:200])
            rec = escape(f.get("recommendation", "")[:200])
            line_display = f.get("line_start", "") or ""
            ai_rows.append(f"""<tr><td>{escape(f['id'])}</td><td>{sev}</td><td>{file_link}</td><td>{line_display}</td>
                <td>{ftitle}{snippet}</td><td style="font-size:12px">{desc}</td><td style="font-size:12px">{rec}</td></tr>""")
        ai_section = f"""
    <section id="ai-review">
        <h2>AI Review Findings ({len(ai_findings)})</h2>
        <p style="color:#8b949e;margin-bottom:12px">Findings from adversarial multi-agent review and semantic security analysis. These are code-level issues that require semantic understanding beyond pattern matching.</p>
        <table>
        <thead><tr><th>ID</th><th>Severity</th><th>File</th><th>Line</th><th>Title</th><th>Evidence</th><th>Fix</th></tr></thead>
        <tbody>{''.join(ai_rows)}</tbody>
        </table>
    </section>"""

    crit_findings = [f for f in all_findings if f["severity"] == "critical" and f.get("category") not in ("sca", "secrets")]
    high_findings = [f for f in all_findings if f["severity"] == "high" and f.get("category") not in ("sca", "secrets")]

    crit_section = f"""
    <section id="critical">
        <h2>Critical SAST Findings ({len(crit_findings)})</h2>
        {_render_findings_table(crit_findings, repo_short, repo_full=repo_full, branch=branch)}
    </section>""" if crit_findings else ""

    high_section = f"""
    <section id="high">
        <h2>High SAST Findings ({len(high_findings)})</h2>
        {_render_findings_table(high_findings, repo_short, repo_full=repo_full, branch=branch)}
    </section>""" if high_findings else ""

    # Multi-repo sections
    repo_sections = ""
    if multi:
        for _, findings, m in all_data:
            repo = m.get("repo", "Unknown")
            rs = repo.split("/")[-1]
            sev = Counter(f["severity"] for f in findings)
            crits = [f for f in findings if f["severity"] == "critical"]
            repo_sections += f"""
            <section id="repo-{escape(rs)}">
                <h2>{escape(repo)}</h2>
                <p>Critical: {sev.get('critical',0)} | High: {sev.get('high',0)} | Medium: {sev.get('medium',0)} | Low: {sev.get('low',0)} | Total: {len(findings)}</p>
                {_render_findings_table(crits, rs, show_detected_by=False) if crits else '<p>No critical findings.</p>'}
            </section>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font: 14px/1.6 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; display: flex; }}
.sidebar {{ width: 220px; background: #161b22; border-right: 1px solid #30363d; padding: 20px 0; position: fixed; height: 100vh; overflow-y: auto; }}
.sidebar h3 {{ padding: 10px 16px; font-size: 12px; text-transform: uppercase; color: #8b949e; letter-spacing: 1px; }}
.sidebar a {{ display: block; padding: 8px 16px; color: #c9d1d9; text-decoration: none; font-size: 13px; border-left: 3px solid transparent; }}
.sidebar a:hover {{ background: #21262d; border-left-color: #58a6ff; }}
.main {{ margin-left: 220px; padding: 32px 40px; flex: 1; max-width: 1200px; }}
h1 {{ font-size: 24px; margin-bottom: 8px; color: #f0f6fc; }}
h2 {{ font-size: 18px; margin: 32px 0 16px; color: #f0f6fc; padding-bottom: 8px; border-bottom: 1px solid #30363d; }}
.meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 16px 0 24px; }}
.meta-item {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; }}
.meta-label {{ display: block; font-size: 11px; text-transform: uppercase; color: #8b949e; margin-bottom: 4px; }}
.meta-value {{ font-size: 16px; font-weight: 600; color: #f0f6fc; }}
.stat-cards {{ display: flex; gap: 12px; margin: 16px 0; flex-wrap: wrap; }}
.stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px 20px; min-width: 100px; }}
.stat-count {{ font-size: 28px; font-weight: 700; color: #f0f6fc; }}
.stat-label {{ font-size: 12px; text-transform: uppercase; color: #8b949e; }}
.donut-container {{ display: flex; align-items: center; gap: 24px; margin: 16px 0; }}
.donut {{ width: 120px; height: 120px; border-radius: 50%; background: conic-gradient({donut_gradient}); position: relative; }}
.donut::after {{ content: '{total}'; position: absolute; inset: 20px; background: #0d1117; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 22px; font-weight: 700; color: #f0f6fc; }}
.legend {{ font-size: 13px; }}
.legend-item {{ display: flex; align-items: center; gap: 8px; margin: 4px 0; }}
.legend-dot {{ width: 12px; height: 12px; border-radius: 3px; }}
table {{ width: 100%; border-collapse: collapse; margin: 8px 0 24px; font-size: 13px; }}
th {{ background: #161b22; padding: 8px 10px; text-align: left; border-bottom: 2px solid #30363d; color: #8b949e; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
td {{ padding: 6px 10px; border-bottom: 1px solid #21262d; }}
tr:hover {{ background: #161b22; }}
code {{ background: #21262d; padding: 2px 6px; border-radius: 3px; font-size: 12px; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; color: #fff; }}
.sev-critical {{ color: #dc3545; font-weight: 600; }}
.sev-high {{ color: #fd7e14; }}
.sev-medium {{ color: #ffc107; }}
.sev-low {{ color: #17a2b8; }}
.sev-info {{ color: #6c757d; }}
.overflow {{ color: #8b949e; font-style: italic; margin: 8px 0; }}
section {{ margin-bottom: 24px; }}
</style>
</head>
<body>
<nav class="sidebar">
    <h3>Navigation</h3>
    {''.join(nav_items)}
</nav>
<div class="main">
    <h1>{escape(title)}</h1>
    {meta_html}

    <section id="summary">
        <h2>Executive Summary</h2>
        <div class="stat-cards">{stat_cards}</div>
        <div class="donut-container">
            <div class="donut"></div>
            <div class="legend">
                {''.join(f'<div class="legend-item"><div class="legend-dot" style="background:{SEV_COLORS[s]}"></div>{s.title()}: {sev_counts.get(s,0)}</div>' for s in ["critical","high","medium","low","info"] if sev_counts.get(s,0))}
            </div>
        </div>
        <h3>Categories</h3>
        <table><thead><tr><th>Category</th><th>Count</th></tr></thead>
        <tbody>{''.join(cat_rows)}</tbody></table>
    </section>

    <section id="tools">
        <h2>Tool Coverage</h2>
        <table>
        <thead><tr><th>Tool</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Total</th></tr></thead>
        <tbody>{''.join(tool_rows)}</tbody>
        </table>
    </section>

    {ai_section}
    {sca_section}
    {secrets_section}
    {crit_section}
    {high_section}
    {repo_sections}

    <footer style="margin-top:40px; padding-top:16px; border-top:1px solid #30363d; color:#8b949e; font-size:12px;">
        Generated by RHOAI Security Audit
    </footer>
</div>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_dirs", nargs="+")
    args = parser.parse_args()
    print(generate_html(args.scan_dirs))


if __name__ == "__main__":
    main()
