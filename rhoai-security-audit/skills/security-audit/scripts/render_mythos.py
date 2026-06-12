#!/usr/bin/env python3
"""Render Mythos security audit markdown reports as a single tabbed HTML file.

Preserves original findings content (CVSS, ASVS, exploit scenarios, remediation
code blocks). Adds: tabbed navigation per component, severity summary dashboard,
dark theme, search, collapsible sections.

Usage:
    python3 render_mythos.py <mythos-dir> -o report.html
    python3 render_mythos.py <mythos-dir>  # outputs to <mythos-dir>/mythos-report.html
"""
import argparse
import re
import sys
from html import escape
from pathlib import Path


SEV_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#17a2b8",
    "informational": "#6c757d",
    "info": "#6c757d",
}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "info": 5}


def parse_severity_counts(text):
    """Extract severity counts from executive summary."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for sev in counts:
        label = "Informational" if sev == "info" else sev.title()
        m = re.search(rf'(\d+)\s+{label}', text[:3000], re.IGNORECASE)
        if m:
            counts[sev] = int(m.group(1))
    # Also try table format: | **Critical** | 1 |
    for row in re.findall(r'\|\s*\*\*(\w+)\*\*\s*\|\s*(\d+)\s*\|', text[:3000]):
        sev = row[0].lower()
        if sev == "informational":
            sev = "info"
        if sev in counts:
            counts[sev] = int(row[1])
    return counts


def md_to_html(md_text):
    """Convert markdown to HTML, preserving code blocks and tables."""
    lines = md_text.split("\n")
    html_parts = []
    in_code = False
    code_lang = ""
    code_lines = []
    in_table = False
    table_lines = []

    for line in lines:
        # Code blocks
        if line.startswith("```"):
            if in_code:
                code = escape("\n".join(code_lines))
                html_parts.append(
                    f'<pre class="code-block"><code class="{code_lang}">{code}</code></pre>'
                )
                code_lines = []
                in_code = False
            else:
                if in_table:
                    html_parts.append(render_table(table_lines))
                    table_lines = []
                    in_table = False
                code_lang = line[3:].strip()
                in_code = True
            continue

        if in_code:
            code_lines.append(line)
            continue

        # Tables
        if line.strip().startswith("|") and "|" in line[1:]:
            if not in_table:
                in_table = True
            table_lines.append(line)
            continue
        elif in_table:
            html_parts.append(render_table(table_lines))
            table_lines = []
            in_table = False

        # Skip horizontal rules
        if line.strip() == "---":
            continue

        # Headings (only h4+ inside findings, h1-h3 handled by structure)
        if line.startswith("####"):
            text = format_inline(line.lstrip("#").strip())
            html_parts.append(f"<h4>{text}</h4>")
            continue

        # Bold section headers: **Description**, **Exploit scenario**, etc.
        if re.match(r'^\*\*\w', line) and line.strip().endswith("**"):
            text = line.strip().strip("*")
            html_parts.append(f'<h4 class="section-header">{escape(text)}</h4>')
            continue
        if re.match(r'^\*\*\w.*\*\*$', line.strip()):
            text = line.strip().strip("*").rstrip(".")
            html_parts.append(f'<h4 class="section-header">{escape(text)}</h4>')
            continue

        # Bullet lists
        if re.match(r'^[-*]\s', line.strip()):
            text = format_inline(line.strip().lstrip("-* "))
            html_parts.append(f"<li>{text}</li>")
            continue
        if re.match(r'^\d+\.\s', line.strip()):
            text = format_inline(re.sub(r'^\d+\.\s*', '', line.strip()))
            html_parts.append(f"<li>{text}</li>")
            continue

        # Empty lines
        if not line.strip():
            html_parts.append("")
            continue

        # Regular paragraphs
        html_parts.append(f"<p>{format_inline(line)}</p>")

    if in_table:
        html_parts.append(render_table(table_lines))
    if in_code:
        code = escape("\n".join(code_lines))
        html_parts.append(f'<pre class="code-block"><code>{code}</code></pre>')

    return "\n".join(html_parts)


def render_table(lines):
    """Render markdown table as HTML."""
    if len(lines) < 2:
        return ""
    rows = []
    for i, line in enumerate(lines):
        cells = [c.strip() for c in line.split("|")[1:-1]]
        if not cells:
            continue
        if i == 1 and all(re.match(r'^[-:]+$', c) for c in cells):
            continue
        tag = "th" if i == 0 else "td"
        row = "".join(f"<{tag}>{format_inline(c)}</{tag}>" for c in cells)
        rows.append(f"<tr>{row}</tr>")
    if not rows:
        return ""
    return f'<table class="finding-table">{"".join(rows)}</table>'


def format_inline(text):
    """Format inline markdown: bold, italic, code, links."""
    text = escape(text)
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
    text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
    return text


def parse_component(filepath):
    """Parse a single Mythos report into structured data."""
    text = Path(filepath).read_text()
    component = Path(filepath).parent.name

    # Executive summary (everything before first FIND)
    first_find = re.search(r'\n### FIND-', text)
    exec_summary = text[:first_find.start()] if first_find else text[:2000]

    # Severity counts
    sev_counts = parse_severity_counts(text)
    total = sum(sev_counts.values())

    # Extract repo info
    repo_match = re.search(r'Repository.*?(https://github\.com/[\w\-/]+)', text)
    repo = repo_match.group(1) if repo_match else ""

    # Split into findings
    parts = re.split(r'\n### (FIND-\d+)', text)
    findings = []
    for i in range(1, len(parts), 2):
        fid = parts[i]
        body = parts[i + 1] if i + 1 < len(parts) else ""

        title_match = re.match(r'\s*—\s*(.+?)(?:\n|$)', body)
        title = title_match.group(1).strip() if title_match else fid

        # Severity from multiple formats
        severity = "medium"
        for pattern in [
            r'—\s*\*\*(\w+)\*\*',
            r'\*\*Severity\*\*\s*\|\s*\*\*(\w+)\*\*',
            r'\*\*Severity:\*\*\s*(\w+)',
            r'CVSS.*?\d+\.\d+\s*\((\w+)\)',
        ]:
            m = re.search(pattern, body, re.MULTILINE)
            if m:
                s = m.group(1).lower()
                if s in SEV_COLORS:
                    severity = s
                    break

        # CVSS
        cvss_match = re.search(r'(\d+\.\d+)', body[:500])
        cvss = cvss_match.group(1) if cvss_match else ""

        # Render body as HTML (skip the title line)
        body_without_title = re.sub(r'^[^\n]*\n', '', body, count=1)
        body_html = md_to_html(body_without_title)

        findings.append({
            "id": fid,
            "title": title,
            "severity": severity,
            "cvss": cvss,
            "html": body_html,
        })

    return {
        "name": component,
        "repo": repo,
        "sev_counts": sev_counts,
        "total": total,
        "findings": findings,
        "exec_summary_html": md_to_html(exec_summary),
    }


def generate_report(mythos_dir, output_path):
    """Generate single tabbed HTML report from all Mythos reports."""
    base = Path(mythos_dir)
    reports = sorted(base.rglob("*-security-audit.md"))

    if not reports:
        print("No Mythos reports found.", file=sys.stderr)
        sys.exit(1)

    # Parse all components
    components = []
    for rpath in reports:
        comp = parse_component(rpath)
        components.append(comp)

    # Sort: components with findings first (by severity), then empty ones
    components.sort(key=lambda c: (
        -c["sev_counts"]["critical"],
        -c["sev_counts"]["high"],
        -c["sev_counts"]["medium"],
        -c["total"],
    ))

    # Global summary
    total_findings = sum(c["total"] for c in components)
    total_critical = sum(c["sev_counts"]["critical"] for c in components)
    total_high = sum(c["sev_counts"]["high"] for c in components)
    total_medium = sum(c["sev_counts"]["medium"] for c in components)
    total_low = sum(c["sev_counts"]["low"] for c in components)
    total_info = sum(c["sev_counts"]["info"] for c in components)
    comps_with_findings = sum(1 for c in components if c["total"] > 0)

    # Read README if present
    readme_path = base / "README.md"
    readme_html = ""
    if readme_path.exists():
        readme_html = md_to_html(readme_path.read_text())

    # Build tab buttons
    tab_buttons = ['<button class="tab-btn active" onclick="showTab(\'overview\')">Overview</button>']
    for c in components:
        if c["total"] == 0:
            continue
        sev_badge = ""
        if c["sev_counts"]["critical"] > 0:
            sev_badge = f'<span class="tab-badge crit">{c["sev_counts"]["critical"]}C</span>'
        elif c["sev_counts"]["high"] > 0:
            sev_badge = f'<span class="tab-badge high">{c["sev_counts"]["high"]}H</span>'
        tab_buttons.append(
            f'<button class="tab-btn" onclick="showTab(\'{c["name"]}\')">'
            f'{escape(c["name"])} {sev_badge}</button>'
        )

    # Build tab content
    tab_contents = []

    # Overview tab
    overview = f'''<div id="tab-overview" class="tab-content active">
    <div class="banner">CONFIDENTIAL — This report may contain undisclosed security findings. Do not share outside authorized personnel.</div>
    <h1>RHOAI Security Audit</h1>
    <div class="stat-row">
        <div class="stat-card" style="border-left:3px solid {SEV_COLORS["critical"]}"><div class="stat-count" style="color:{SEV_COLORS["critical"]}">{total_critical}</div><div class="stat-label">Critical</div></div>
        <div class="stat-card" style="border-left:3px solid {SEV_COLORS["high"]}"><div class="stat-count" style="color:{SEV_COLORS["high"]}">{total_high}</div><div class="stat-label">High</div></div>
        <div class="stat-card" style="border-left:3px solid {SEV_COLORS["medium"]}"><div class="stat-count" style="color:{SEV_COLORS["medium"]}">{total_medium}</div><div class="stat-label">Medium</div></div>
        <div class="stat-card" style="border-left:3px solid {SEV_COLORS["low"]}"><div class="stat-count" style="color:{SEV_COLORS["low"]}">{total_low}</div><div class="stat-label">Low</div></div>
        <div class="stat-card" style="border-left:3px solid {SEV_COLORS["info"]}"><div class="stat-count" style="color:{SEV_COLORS["info"]}">{total_info}</div><div class="stat-label">Info</div></div>
        <div class="stat-card"><div class="stat-count">{total_findings}</div><div class="stat-label">Total</div></div>
    </div>
    <p class="meta">{comps_with_findings} components with findings out of {len(components)} scanned</p>
    {readme_html}
</div>'''
    tab_contents.append(overview)

    # Component tabs
    for c in components:
        if c["total"] == 0:
            continue

        findings_html = ""
        for f in c["findings"]:
            sev = f["severity"]
            color = SEV_COLORS.get(sev, "#6c757d")
            cvss_badge = f'<span class="cvss-badge">CVSS {f["cvss"]}</span>' if f["cvss"] else ""
            sev_chip = f'<span class="chip" style="background:{color}">{sev.upper()}</span>'

            findings_html += f'''<div class="finding-card" style="border-left-color:{color}">
    <div class="finding-header" onclick="this.parentElement.classList.toggle('expanded')">
        {sev_chip} {cvss_badge}
        <span class="finding-id">{f["id"]}</span>
        <span class="finding-title">{escape(f["title"][:120])}</span>
        <span class="expand-icon">&#9660;</span>
    </div>
    <div class="finding-body">{f["html"]}</div>
</div>\n'''

        sev_summary = " · ".join(
            f'<span style="color:{SEV_COLORS.get(s, "#ccc")}">{c["sev_counts"][s]} {s.title()}</span>'
            for s in ["critical", "high", "medium", "low", "info"]
            if c["sev_counts"][s] > 0
        )

        tab_contents.append(f'''<div id="tab-{c["name"]}" class="tab-content">
    <h2>{escape(c["name"])}</h2>
    <p class="meta">{sev_summary} · {c["total"]} findings</p>
    {c["exec_summary_html"]}
    <h3>Findings</h3>
    {findings_html}
</div>''')

    # Assemble HTML
    html = f'''<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>RHOAI Security Audit - Mythos</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font:14px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#0d1117; color:#c9d1d9; }}
a {{ color:#58a6ff; text-decoration:none; }}
h1 {{ font-size:22px; color:#f0f6fc; margin:16px 0 8px; }}
h2 {{ font-size:18px; color:#f0f6fc; margin:16px 0 8px; }}
h3 {{ font-size:15px; color:#f0f6fc; margin:16px 0 8px; border-bottom:1px solid #21262d; padding-bottom:6px; }}
h4 {{ font-size:13px; color:#e6edf3; margin:10px 0 4px; }}
.section-header {{ color:#8b949e; font-size:12px; text-transform:uppercase; letter-spacing:0.5px; margin:14px 0 6px; }}
p {{ margin:4px 0; }}
li {{ margin:2px 0 2px 20px; }}
code {{ background:#161b22; padding:1px 5px; border-radius:3px; font-size:12px; color:#e6edf3; }}
.code-block {{ background:#0d1117; border:1px solid #21262d; border-radius:6px; padding:10px 12px; font-size:12px; overflow-x:auto; margin:8px 0; color:#e6edf3; white-space:pre; }}
.banner {{ background:#dc354520; border:1px solid #dc3545; border-radius:6px; padding:8px 14px; margin:16px 24px; font-size:12px; color:#f0f6fc; text-align:center; }}
.banner strong {{ color:#dc3545; }}
.meta {{ color:#8b949e; font-size:12px; margin:4px 0 12px; }}

/* Tabs */
.tab-bar {{ display:flex; flex-wrap:wrap; gap:2px; padding:8px 16px; background:#161b22; border-bottom:1px solid #21262d; position:sticky; top:0; z-index:10; overflow-x:auto; }}
.tab-btn {{ background:none; border:none; color:#8b949e; padding:6px 12px; font-size:12px; cursor:pointer; border-radius:4px 4px 0 0; white-space:nowrap; }}
.tab-btn:hover {{ background:#21262d; color:#c9d1d9; }}
.tab-btn.active {{ background:#0d1117; color:#f0f6fc; border-bottom:2px solid #58a6ff; }}
.tab-badge {{ font-size:9px; padding:1px 4px; border-radius:6px; color:#fff; margin-left:3px; }}
.tab-badge.crit {{ background:#dc3545; }}
.tab-badge.high {{ background:#fd7e14; }}
.tab-content {{ display:none; padding:16px 24px; max-width:1100px; margin:0 auto; }}
.tab-content.active {{ display:block; }}

/* Stats */
.stat-row {{ display:flex; gap:10px; margin:12px 0; flex-wrap:wrap; }}
.stat-card {{ background:#161b22; border:1px solid #30363d; border-radius:6px; padding:10px 16px; text-align:center; }}
.stat-count {{ font-size:24px; font-weight:700; }}
.stat-label {{ font-size:10px; text-transform:uppercase; color:#8b949e; }}

/* Findings */
.finding-card {{ background:#161b22; border:1px solid #30363d; border-left:3px solid #6c757d; border-radius:6px; margin:6px 0; overflow:hidden; }}
.finding-header {{ display:flex; align-items:center; gap:6px; padding:10px 14px; cursor:pointer; flex-wrap:wrap; }}
.finding-header:hover {{ background:#1c2128; }}
.finding-id {{ color:#8b949e; font-size:11px; font-weight:600; }}
.finding-title {{ color:#f0f6fc; font-size:13px; flex:1; }}
.expand-icon {{ color:#8b949e; font-size:10px; transition:transform 0.2s; }}
.finding-card.expanded .expand-icon {{ transform:rotate(180deg); }}
.finding-body {{ display:none; padding:0 14px 14px; font-size:12px; border-top:1px solid #21262d; }}
.finding-card.expanded .finding-body {{ display:block; }}
.chip {{ display:inline-block; padding:1px 7px; border-radius:10px; font-size:10px; font-weight:600; color:#fff; }}
.cvss-badge {{ font-size:10px; color:#8b949e; background:#21262d; padding:1px 6px; border-radius:4px; }}

/* Tables */
.finding-table {{ width:100%; border-collapse:collapse; font-size:12px; margin:8px 0; }}
.finding-table th {{ background:#0d1117; padding:5px 8px; text-align:left; border-bottom:1px solid #30363d; color:#8b949e; font-weight:600; font-size:10px; }}
.finding-table td {{ padding:4px 8px; border-bottom:1px solid #161b22; }}
.finding-table tr:hover {{ background:#1c2128; }}
</style>
</head><body>

<div class="tab-bar">
{"".join(tab_buttons)}
</div>

{"".join(tab_contents)}

<script>
function showTab(name) {{
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('tab-' + name).classList.add('active');
    event.target.classList.add('active');
}}
</script>
</body></html>'''

    Path(output_path).write_text(html)
    print(f"Report: {output_path} ({len(html) // 1024}KB)")
    print(f"Components: {len(components)} ({comps_with_findings} with findings)")
    print(f"Findings: {total_findings}")


def generate_mkdocs_site(mythos_dir, output_dir):
    """Generate a MkDocs Material site with per-component pages."""
    import shutil
    import subprocess

    base = Path(mythos_dir)
    reports = sorted(base.rglob("*-security-audit.md"))
    if not reports:
        print("No Mythos reports found.", file=sys.stderr)
        sys.exit(1)

    components = []
    for rpath in reports:
        comp = parse_component(rpath)
        components.append(comp)

    components.sort(key=lambda c: (
        -c["sev_counts"]["critical"],
        -c["sev_counts"]["high"],
        -c["total"],
    ))

    out = Path(output_dir)
    docs_dir = out / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)

    total_findings = sum(c["total"] for c in components)
    comps_with = [c for c in components if c["total"] > 0]
    comps_empty = [c for c in components if c["total"] == 0]

    # Index page
    index = "# RHOAI Security Audit\n\n"
    index += "> **CONFIDENTIAL** — Do not share outside authorized personnel.\n\n"
    index += f"**{total_findings} findings** across **{len(comps_with)} components** ({len(comps_empty)} clean)\n\n"
    index += "| Component | Critical | High | Medium | Low | Info | Total |\n"
    index += "|-----------|----------|------|--------|-----|------|-------|\n"
    for c in components:
        s = c["sev_counts"]
        crit_mark = f"**{s['critical']}**" if s["critical"] else "0"
        high_mark = f"**{s['high']}**" if s["high"] else "0"
        total_mark = f"**{c['total']}**" if c["total"] else "0"
        index += (f"| [{c['name']}](components/{c['name']}.md) | {crit_mark} | {high_mark} | "
                  f"{s['medium']} | {s['low']} | {s['info']} | {total_mark} |\n")
    (docs_dir / "index.md").write_text(index)

    # Per-component pages (ALL components, including empty)
    comp_dir = docs_dir / "components"
    comp_dir.mkdir(exist_ok=True)

    for c in components:
        if c["total"] == 0:
            md = f"# {c['name']}\n\n"
            md += "!!! success \"No findings\"\n    No security findings identified for this component.\n"
            if c["repo"]:
                md += f"\n**Repository:** {c['repo']}\n"
            (comp_dir / f"{c['name']}.md").write_text(md)
            continue

        c_with_findings = c
        c = c_with_findings
        s = c["sev_counts"]
        sev_line = " · ".join(
            f"**{s[sv]} {sv.title()}**" for sv in ["critical", "high", "medium", "low", "info"]
            if s[sv] > 0
        )

        md = f"# {c['name']}\n\n"
        md += f"{sev_line} · {c['total']} findings\n\n"
        if c["repo"]:
            md += f"**Repository:** {c['repo']}\n\n"

        for f in c["findings"]:
            sev = f["severity"]
            admon = {"critical": "danger", "high": "warning", "medium": "note",
                     "low": "info", "informational": "tip", "info": "tip"}.get(sev, "note")
            cvss_text = f" (CVSS {f['cvss']})" if f["cvss"] else ""

            md += f'??? {admon} "{f["id"]} — {escape(f["title"][:100])}{cvss_text}"\n\n'

            # Re-render finding body preserving original content
            body_lines = f["html"].replace("<h4>", "\n    **").replace("</h4>", "**\n")
            body_lines = re.sub(r'<pre class="code-block"><code[^>]*>(.*?)</code></pre>',
                                lambda m: "\n    ```\n    " + m.group(1).replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("\n", "\n    ") + "\n    ```\n",
                                body_lines, flags=re.DOTALL)
            body_lines = re.sub(r'<table[^>]*>.*?</table>', '', body_lines, flags=re.DOTALL)
            body_lines = re.sub(r'<p>(.*?)</p>', r'\1', body_lines)
            body_lines = re.sub(r'<li>(.*?)</li>', r'- \1', body_lines)
            body_lines = re.sub(r'<strong>(.*?)</strong>', r'**\1**', body_lines)
            body_lines = re.sub(r'<em>(.*?)</em>', r'*\1*', body_lines)
            body_lines = re.sub(r'<code>(.*?)</code>', r'`\1`', body_lines)
            body_lines = re.sub(r'<[^>]+>', '', body_lines)

            for line in body_lines.split("\n"):
                stripped = line.strip()
                if stripped:
                    md += f"    {stripped}\n"
                else:
                    md += "\n"
            md += "\n"

        (comp_dir / f"{c['name']}.md").write_text(md)

    # Nav entries (all components)
    nav_comps = "\n".join(
        f"      - {c['name']}: components/{c['name']}.md"
        for c in components
    )

    yml = f"""site_name: "RHOAI Security Audit"
use_directory_urls: false
copyright: "CONFIDENTIAL — Red Hat, Inc. — Do not share outside authorized personnel"

theme:
  name: material
  language: en
  icon:
    logo: material/shield-lock
  font:
    text: Red Hat Text
    code: Red Hat Mono
  palette:
    - scheme: default
      primary: black
      toggle:
        icon: material/brightness-4
        name: Switch to dark mode
    - scheme: slate
      primary: black
      toggle:
        icon: material/brightness-7
        name: Switch to light mode
  features:
    - navigation.tabs
    - navigation.top
    - navigation.indexes
    - navigation.path
    - navigation.expand
    - search.suggest
    - search.highlight
    - content.code.copy
    - toc.follow

plugins:
  - search

markdown_extensions:
  - admonition
  - pymdownx.details
  - pymdownx.superfences
  - pymdownx.highlight:
      anchor_linenums: true
  - pymdownx.inlinehilite
  - attr_list
  - md_in_html
  - tables
  - toc:
      permalink: true

extra_css:
  - custom.css

extra_javascript:
  - footer-fix.js

nav:
  - Overview: index.md
  - Components:
{nav_comps}
"""
    (out / "mkdocs.yml").write_text(yml)

    css = """\
/* Body and container fill viewport, push footer to bottom */
body {
  display: flex !important;
  flex-direction: column !important;
  min-height: 100vh !important;
}
.md-header { flex-shrink: 0 !important; }
.md-container {
  display: flex !important;
  flex-direction: column !important;
  flex: 1 !important;
}
.md-tabs { flex-shrink: 0 !important; }
.md-main { flex: 1 !important; }
.md-footer { flex-shrink: 0 !important; }

/* Reduce footer padding */
.md-footer-meta { padding: 0.2rem 0 !important; }
.md-footer-meta__inner { padding: 0.1rem !important; }

/* Reduce sidebar bottom gap */
.md-sidebar { padding-bottom: 0.4rem !important; }

/* Hide "Made with Material for MkDocs" */
.md-copyright { font-size: 0 !important; line-height: 0 !important; }
.md-copyright__highlight { font-size: 0.64rem !important; line-height: 1.4 !important; }
.md-copyright a { display: none !important; }
"""
    (docs_dir / "custom.css").write_text(css)

    js = """\
// Ensure footer stays at viewport bottom after Material's JS runs
document.addEventListener('DOMContentLoaded', function() {
  var footer = document.querySelector('.md-footer');
  if (!footer) return;
  function fixFooter() {
    var body = document.body;
    var docHeight = body.scrollHeight;
    var winHeight = window.innerHeight;
    if (docHeight <= winHeight) {
      footer.style.position = 'fixed';
      footer.style.bottom = '0';
      footer.style.left = '0';
      footer.style.right = '0';
      footer.style.zIndex = '4';
      body.style.paddingBottom = (footer.offsetHeight + 4) + 'px';
    } else {
      footer.style.position = '';
      footer.style.bottom = '';
      footer.style.left = '';
      footer.style.right = '';
      footer.style.zIndex = '';
      body.style.paddingBottom = '';
    }
  }
  fixFooter();
  window.addEventListener('resize', fixFooter);
  new MutationObserver(fixFooter).observe(document.body, {childList: true, subtree: true});
});
"""
    (docs_dir / "footer-fix.js").write_text(js)

    # Build
    try:
        result = subprocess.run(
            ["mkdocs", "build", "--config-file", str(out / "mkdocs.yml"),
             "--site-dir", str(out / "site")],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            subprocess.run(
                ["mkdocs", "build", "--config-file", str(out / "mkdocs.yml"),
                 "--site-dir", str(out / "site")],
                capture_output=True, text=True, timeout=60,
            )

        # Zip
        site_dir = out / "site"
        if site_dir.exists():
            shutil.make_archive(str(out / "mythos-report-site"), "zip", str(site_dir))
            print(f"MkDocs site: {site_dir / 'index.html'}")
            print(f"Zip: {out / 'mythos-report-site.zip'}")
    except FileNotFoundError:
        print("mkdocs not found. Install: pip install mkdocs-material", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mythos_dir")
    parser.add_argument("-o", "--output", default=None)
    parser.add_argument("--mkdocs", action="store_true", help="Generate MkDocs site with per-component pages")
    args = parser.parse_args()

    if args.mkdocs:
        output = args.output or str(Path(args.mythos_dir) / "mkdocs-report")
        generate_mkdocs_site(args.mythos_dir, output)
    else:
        output = args.output or str(Path(args.mythos_dir) / "mythos-report.html")
        generate_report(args.mythos_dir, output)


if __name__ == "__main__":
    main()
