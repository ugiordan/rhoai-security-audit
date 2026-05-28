#!/usr/bin/env python3
"""Generate self-contained HTML security report.

Card-based layout optimized for triage:
- Stat cards + donut chart at top
- Filter chips (severity, source, triage status)
- Finding cards with severity border, triage badges, code snippets
- Collapsible dependency CVEs and tool coverage
- GitHub permalink file:line links
- Self-contained: all CSS + JS inline, no external deps

Usage:
    python3 report_html.py <scan-dir> > report.html
    python3 report_html.py <scan-dir1> <scan-dir2> > multi-report.html
"""
import argparse
import json
from collections import Counter, defaultdict
from html import escape
from pathlib import Path

SEV_COLORS = {
    "critical": "#dc3545", "high": "#fd7e14", "medium": "#ffc107",
    "low": "#17a2b8", "info": "#6c757d",
}

TRIAGE_BADGES = {
    "corroborated": '<span class="chip" style="background:#16a34a;margin-left:4px" title="Found by both SAST and AI">CORR</span>',
    "ai-only": '<span class="chip" style="background:#2563eb;margin-left:4px" title="AI-only finding (logic bug)">AI</span>',
    "sast-only": "",
}

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SOURCE_COLORS = {
    "adversarial-review": "#2563eb", "semantic-scan": "#7c3aed",
}
TRIAGE_LABELS = {
    "corroborated": ("CORR", "#16a34a", "Found by both SAST and AI"),
    "ai-only": ("AI", "#2563eb", "AI-only finding (logic bug)"),
}
CAT_LABELS = {
    "secrets": "Secrets", "sca": "CVEs / SCA", "k8s": "Kubernetes",
    "config": "Configuration", "cicd": "CI/CD", "injection": "Injection",
    "ai-review": "AI Review", "other": "SAST",
}


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
    p = Path(scan_dir)
    meta = {}
    f = p / "scan-metadata.json"
    if f.exists():
        meta = json.loads(f.read_text())
    ci = p / "raw" / "commit-info.json"
    if ci.exists():
        try:
            info = json.loads(ci.read_text())
            if not meta.get("branch"):
                meta["branch"] = info.get("default_branch", "main")
            if not meta.get("commit"):
                meta["commit"] = info.get("commit_sha", "")
        except Exception:
            pass
    if not meta.get("repo"):
        parts = Path(scan_dir).resolve().parts
        for i, part in enumerate(parts):
            if part == "output" and i + 1 < len(parts):
                meta["repo"] = f"opendatahub-io/{parts[i + 1]}"
                break
    return meta


def load_ai_findings(scan_dir):
    import re
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
            blocks = re.split(r'\n(?=(?:Finding ID:|###?\s+(?:SEC|PERF|QUAL|CORR|ARCH|FINDING)-\d+))', text)
            for block in blocks:
                id_match = re.search(r'(?:Finding ID:\s*|###?\s+)((?:SEC|PERF|QUAL|CORR|ARCH|FINDING)-\d+)', block)
                if not id_match:
                    continue
                f = {"id": id_match.group(1), "source": source, "origin": "ai",
                     "category": "ai-review", "detected_by": [source]}
                sev_match = re.search(r'Severity:\s*(\w+)', block, re.IGNORECASE)
                sev = sev_match.group(1).lower() if sev_match else "medium"
                f["severity"] = {"critical": "critical", "important": "high", "high": "high",
                                 "medium": "medium", "minor": "low"}.get(sev, "medium")
                title_match = re.search(r'Title:\s*(.+?)(?:\n|$)', block)
                f["title"] = title_match.group(1).strip() if title_match else f["id"]
                file_match = re.search(r'File:\s*`?([^\n`]+)`?', block)
                f["file"] = file_match.group(1).strip() if file_match else ""
                line_match = re.search(r'Lines?:\s*(\d+)', block)
                f["line_start"] = int(line_match.group(1)) if line_match else 0
                f["line_end"] = f["line_start"]
                evidence_match = re.search(r'Evidence:\s*(.+?)(?=\n(?:Impact|Recommended|Finding ID:|\Z))', block, re.DOTALL)
                f["description"] = evidence_match.group(1).strip()[:500] if evidence_match else ""
                fix_match = re.search(r'Recommended fix:\s*(.+?)(?=\n(?:Finding ID:|\Z))', block, re.DOTALL)
                f["recommendation"] = fix_match.group(1).strip()[:300] if fix_match else ""
                f["triage"] = {}
                ai_findings.append(f)
    return ai_findings


def _github_url(filepath, line_start, line_end, repo_full, ref):
    if not repo_full or not filepath:
        return ""
    url_path = filepath
    parts = filepath.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p in ("repo", "repos"):
            url_path = "/".join(parts[i + 2:]) if i + 2 <= len(parts) else filepath
            break
    frag = f"#L{line_start}" if line_start else ""
    if line_end and line_end != line_start and line_start:
        frag = f"#L{line_start}-L{line_end}"
    return f"https://github.com/{repo_full}/blob/{ref}/{url_path}{frag}"


def _file_display(filepath, line_start):
    url_path = filepath
    parts = filepath.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p in ("repo", "repos"):
            url_path = "/".join(parts[i + 2:]) if i + 2 <= len(parts) else filepath
            break
    return f"{url_path}:{line_start}" if line_start else url_path


def _render_card(f, repo_full, branch_ref, commit_ref):
    sev = f.get("severity", "info")
    color = SEV_COLORS.get(sev, "#6c757d")
    ref = branch_ref if f.get("origin") == "ai" and branch_ref else (commit_ref or branch_ref or "main")
    fpath = f.get("file", "")
    line = f.get("line_start", 0)
    line_end = f.get("line_end", 0)
    url = _github_url(fpath, line, line_end, repo_full, ref)
    display = _file_display(fpath, line)
    source = f.get("source", "")
    triage_status = f.get("triage", {}).get("status", "")
    title_text = escape(f.get("title", "")[:100])
    raw_desc = f.get("description", "")
    snippet = f.get("snippet", "")
    rec = f.get("recommendation", "")
    fid = escape(f.get("id", ""))

    # Extract remediation from description if recommendation is empty
    if not rec and "Remediation:" in raw_desc:
        parts = raw_desc.split("Remediation:", 1)
        raw_desc = parts[0].strip()
        rec = parts[1].strip()

    desc = escape(raw_desc[:300])
    rec = escape(rec[:300])

    triage_badge = TRIAGE_BADGES.get(triage_status, "")
    sev_badge = f'<span class="chip" style="background:{color};color:#fff">{sev.upper()}</span>{triage_badge}'

    src_badge = ""
    if source:
        src_color = SOURCE_COLORS.get(source, "#30363d")
        src_text_color = "#fff" if src_color != "#30363d" else "#8b949e"
        src_badge = f'<span class="chip" style="background:{src_color};color:{src_text_color}">{escape(source)}</span>'

    file_link = f'<a href="{url}" class="file-link" target="_blank">{escape(display)} ↗</a>' if url else f'<code>{escape(display)}</code>'

    snippet_html = ""
    if snippet:
        lines = snippet.strip().split("\n")
        if len(lines) > 6:
            lines = lines[:6] + ["..."]
        snippet_html = f'<pre class="snippet"><code>{escape(chr(10).join(lines))}</code></pre>'

    expand_id = f"expand-{fid}"
    rec_html = ""
    if rec:
        rec_html = f'''<div class="card-expand" id="{expand_id}" style="display:none">
            <div class="card-fix"><span class="fix-label">Fix:</span> {rec}</div>
        </div>
        <div class="card-toggle" onclick="var e=document.getElementById('{expand_id}');e.style.display=e.style.display==='none'?'block':'none';this.textContent=e.style.display==='none'?'Show fix ▾':'Hide fix ▴'">Show fix ▾</div>'''

    return f'''<div class="finding-card" data-severity="{sev}" data-source="{escape(source)}" data-triage="{triage_status}" data-origin="{f.get('origin','sast')}" style="border-left-color:{color}">
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


def generate_html(scan_dirs):
    all_data = []
    for d in scan_dirs:
        findings = load_findings(d)
        metadata = load_metadata(d)
        if findings or metadata:
            all_data.append((d, findings, metadata))

    if not all_data:
        return "<html><body style='background:#0d1117;color:#c9d1d9;padding:40px'><h1>No scan data found.</h1></body></html>"

    all_findings = []
    for _, f, _ in all_data:
        all_findings.extend(f)

    ai_findings = [f for f in all_findings if f.get("origin") == "ai"]
    if not ai_findings:
        for d in scan_dirs:
            loaded = load_ai_findings(d)
            ai_findings.extend(loaded)
            all_findings.extend(loaded)

    first_meta = all_data[0][2]
    repo_full = first_meta.get("repo", "")
    repo_short = repo_full.split("/")[-1] if repo_full else "Unknown"
    branch_ref = first_meta.get("branch", "main")
    commit_ref = first_meta.get("commit", "")
    date = first_meta.get("date", first_meta.get("scan_date", ""))
    total = len(all_findings)

    sev_counts = Counter(f["severity"] for f in all_findings)
    source_counts = Counter(f.get("source", "unknown") for f in all_findings)
    triage_counts = Counter(f.get("triage", {}).get("status", "sast-only") for f in all_findings)

    # Donut
    donut_segments = []
    offset = 0
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = sev_counts.get(sev, 0)
        if not count:
            continue
        pct = (count / max(total, 1)) * 100
        donut_segments.append(f"{SEV_COLORS[sev]} {offset}% {offset + pct}%")
        offset += pct
    donut_gradient = ", ".join(donut_segments) if donut_segments else "#333 0% 100%"

    # Stat cards
    stat_cards = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        c = sev_counts.get(sev, 0)
        stat_cards += f'<div class="stat-card" style="border-left:3px solid {SEV_COLORS[sev]}"><div class="stat-count" style="color:{SEV_COLORS[sev]}">{c}</div><div class="stat-label">{sev.title()}</div></div>'

    # Filter chips
    sev_chips = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        c = sev_counts.get(sev, 0)
        if not c:
            continue
        active = "active" if sev in ("critical", "high") else ""
        sev_chips += f'<span class="filter-chip {active}" data-filter="severity" data-value="{sev}" style="--active-bg:{SEV_COLORS[sev]}" onclick="toggleFilter(this)">{sev.title()} {c}</span>'

    source_chips = ""
    for src in sorted(source_counts.keys()):
        c = source_counts[src]
        color = SOURCE_COLORS.get(src, "#30363d")
        source_chips += f'<span class="filter-chip active" data-filter="source" data-value="{escape(src)}" style="--active-bg:{color}" onclick="toggleFilter(this)">{escape(src)} {c}</span>'

    triage_chips = ""
    for ts in ["corroborated", "ai-only", "sast-only"]:
        c = triage_counts.get(ts, 0)
        if not c:
            continue
        color = TRIAGE_LABELS.get(ts, ("", "#30363d", ""))[1] if ts in TRIAGE_LABELS else "#30363d"
        triage_chips += f'<span class="filter-chip active" data-filter="triage" data-value="{ts}" style="--active-bg:{color}" onclick="toggleFilter(this)">{ts} {c}</span>'

    # Finding cards (sorted by severity)
    sorted_findings = sorted(all_findings, key=lambda f: (-SEV_RANK.get(f.get("severity", ""), 0), f.get("file", "")))
    non_sca = [f for f in sorted_findings if f.get("category") != "sca"]
    sca_findings = [f for f in sorted_findings if f.get("category") == "sca"]

    finding_cards = "\n".join(_render_card(f, repo_full, branch_ref, commit_ref) for f in non_sca)

    # Collapsible CVE section
    sca_section = ""
    if sca_findings:
        sca_rows = []
        for f in sca_findings[:100]:
            sev_badge = f'<span class="chip" style="background:{SEV_COLORS.get(f["severity"],"#6c757d")};color:#fff;font-size:10px">{f["severity"].upper()}</span>'
            url = _github_url(f.get("file", ""), f.get("line_start", 0), 0, repo_full, commit_ref or branch_ref)
            display = _file_display(f.get("file", ""), f.get("line_start", 0))
            link = f'<a href="{url}" class="file-link" target="_blank">{escape(display)}</a>' if url else f'<code>{escape(display)}</code>'
            sca_rows.append(f'<tr><td>{sev_badge}</td><td>{escape(f.get("source",""))}</td><td>{link}</td><td>{escape(f.get("title","")[:60])}</td><td>{escape(f.get("recommendation","")[:80])}</td></tr>')
        sca_section = f'''<h3 style="color:#f0f6fc;margin-bottom:12px">Dependency Vulnerabilities ({len(sca_findings)} CVEs)</h3>
    <table><thead><tr><th>Severity</th><th>Tool</th><th>File</th><th>Title</th><th>Fix</th></tr></thead>
    <tbody>{"".join(sca_rows)}</tbody></table>'''

    # Collapsible tool coverage
    tool_sev = defaultdict(Counter)
    for f in all_findings:
        tool_sev[f.get("source", "unknown")][f["severity"]] += 1
    meta_findings = first_meta.get("findings", {})
    for tk, tc in meta_findings.items():
        tn = tk.replace("_", "-")
        if tn not in tool_sev:
            tool_sev[tn] = Counter()

    tool_rows = []
    for tool in sorted(tool_sev.keys()):
        s = tool_sev[tool]
        t = sum(s.values())
        cells = "".join(f'<td class="sev-{sv}">{s.get(sv,0) or ""}</td>' for sv in ["critical","high","medium","low","info"])
        style = ' style="color:#4a5568"' if t == 0 else ""
        tool_rows.append(f"<tr{style}><td><strong>{escape(tool)}</strong></td>{cells}<td><strong>{t}</strong></td></tr>")

    tools_section = f'''<h3 style="color:#f0f6fc;margin-bottom:12px">Tool Coverage ({len(tool_sev)} tools)</h3>
    <table><thead><tr><th>Tool</th><th>Crit</th><th>High</th><th>Med</th><th>Low</th><th>Info</th><th>Total</th></tr></thead>
    <tbody>{"".join(tool_rows)}</tbody></table>'''

    # Triage summary in footer
    demoted = triage_counts.get("demoted", 0) + sum(1 for f in all_findings if f.get("triage", {}).get("demoted_from"))
    footer_parts = [f"{total} findings", f"{len(tool_sev)} tools"]
    if triage_counts.get("corroborated"):
        footer_parts.append(f'{triage_counts["corroborated"]} corroborated')
    if triage_counts.get("ai-only"):
        footer_parts.append(f'{triage_counts["ai-only"]} AI-only')
    if demoted:
        footer_parts.append(f'{demoted} demoted')

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Report: {escape(repo_short)}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font:14px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#0d1117; color:#c9d1d9; padding:24px 40px; max-width:1100px; margin:0 auto; }}
a {{ color:#58a6ff; text-decoration:none; }}
a:hover {{ text-decoration:underline; }}
h1 {{ font-size:20px; color:#f0f6fc; margin-bottom:2px; }}
.header-meta {{ color:#4a5568; font-size:12px; margin-bottom:16px; }}
.stat-row {{ display:flex; gap:10px; margin:12px 0; align-items:center; flex-wrap:wrap; }}
.stat-card {{ background:#161b22; border:1px solid #30363d; border-radius:6px; padding:10px 16px; text-align:center; }}
.stat-count {{ font-size:24px; font-weight:700; }}
.stat-label {{ font-size:10px; text-transform:uppercase; color:#8b949e; }}
.donut {{ width:80px; height:80px; border-radius:50%; background:conic-gradient({donut_gradient}); position:relative; margin-left:auto; }}
.donut::after {{ content:'{total}'; position:absolute; inset:14px; background:#0d1117; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:16px; font-weight:700; color:#f0f6fc; }}
.filter-bar {{ padding:12px 0; border-bottom:1px solid #21262d; margin-bottom:12px; }}
.filter-row {{ display:flex; gap:4px; flex-wrap:wrap; align-items:center; margin-bottom:6px; }}
.filter-row:last-child {{ margin-bottom:0; }}
.filter-label {{ font-size:10px; color:#8b949e; margin-right:4px; min-width:55px; }}
.filter-chip {{ padding:3px 10px; border-radius:12px; font-size:11px; font-weight:500; cursor:pointer; background:#30363d; color:#8b949e; border:1px solid transparent; transition:all .15s; user-select:none; }}
.filter-chip.active {{ background:var(--active-bg,#30363d); color:#fff; border-color:rgba(255,255,255,.1); }}
.filter-chip:hover {{ opacity:.85; }}
.counter {{ font-size:11px; color:#8b949e; margin-bottom:10px; }}
.finding-card {{ background:#161b22; border:1px solid #30363d; border-left:3px solid #6c757d; border-radius:6px; padding:12px 14px; margin-bottom:8px; transition:border-color .15s; }}
.finding-card:hover {{ border-color:#58a6ff; }}
.finding-card.hidden {{ display:none; }}
.card-header {{ display:flex; align-items:center; gap:6px; flex-wrap:wrap; margin-bottom:4px; }}
.card-title {{ color:#f0f6fc; font-size:13px; font-weight:500; }}
.card-file {{ margin-left:auto; font-size:11px; }}
.file-link {{ color:#58a6ff; font-size:11px; }}
.card-desc {{ font-size:12px; color:#c9d1d9; margin-top:4px; }}
.chip {{ display:inline-block; padding:1px 7px; border-radius:10px; font-size:10px; font-weight:600; color:#fff; white-space:nowrap; }}
.snippet {{ background:#0d1117; border:1px solid #21262d; padding:6px 8px; border-radius:4px; font-size:11px; margin-top:6px; overflow-x:auto; color:#e6edf3; }}
.card-expand {{ padding:8px 0 4px; border-top:1px solid #21262d; margin-top:8px; font-size:12px; }}
.fix-label {{ color:#8b949e; font-weight:600; font-size:11px; text-transform:uppercase; }}
.card-toggle {{ color:#58a6ff; font-size:11px; cursor:pointer; margin-top:4px; }}
.card-toggle:hover {{ text-decoration:underline; }}
.collapsible {{ background:#161b22; border:1px solid #30363d; border-radius:6px; margin:16px 0 8px; }}
.collapsible summary {{ padding:10px 14px; cursor:pointer; display:flex; align-items:center; gap:8px; list-style:none; }}
.collapsible summary::-webkit-details-marker {{ display:none; }}
.collapsible summary::before {{ content:'▸'; color:#8b949e; font-size:14px; transition:transform .2s; }}
.collapsible[open] summary::before {{ transform:rotate(90deg); }}
.collapse-title {{ color:#f0f6fc; font-size:13px; font-weight:500; }}
.collapse-hint {{ color:#4a5568; font-size:10px; margin-left:auto; }}
.collapse-body {{ padding:0 14px 14px; }}
table {{ width:100%; border-collapse:collapse; font-size:12px; }}
th {{ background:#0d1117; padding:6px 8px; text-align:left; border-bottom:1px solid #30363d; color:#8b949e; font-weight:600; text-transform:uppercase; font-size:10px; }}
td {{ padding:5px 8px; border-bottom:1px solid #161b22; }}
tr:hover {{ background:#0d1117; }}
code {{ background:#21262d; padding:1px 5px; border-radius:3px; font-size:11px; }}
.sev-critical {{ color:#dc3545; }} .sev-high {{ color:#fd7e14; }} .sev-medium {{ color:#ffc107; }}
.sev-low {{ color:#17a2b8; }} .sev-info {{ color:#6c757d; }}
.tabs {{ display:flex; gap:0; border-bottom:2px solid #21262d; margin:16px 0 0; }}
.tab {{ padding:8px 20px; font-size:13px; font-weight:500; color:#8b949e; cursor:pointer; border-bottom:2px solid transparent; margin-bottom:-2px; transition:all .15s; user-select:none; }}
.tab:hover {{ color:#c9d1d9; }}
.tab.active {{ color:#f0f6fc; border-bottom-color:#58a6ff; }}
.tab-badge {{ background:#30363d; color:#8b949e; padding:1px 6px; border-radius:8px; font-size:10px; margin-left:4px; }}
.tab-panel {{ display:none; padding-top:12px; }}
.tab-panel.active {{ display:block; }}
.footer {{ margin-top:32px; padding-top:12px; border-top:1px solid #21262d; color:#4a5568; font-size:11px; }}
@media (max-width:700px) {{
  body {{ padding:12px; }}
  .stat-row {{ gap:6px; }}
  .stat-card {{ padding:6px 10px; }}
  .stat-count {{ font-size:18px; }}
  .card-header {{ font-size:12px; }}
  .donut {{ width:60px; height:60px; }}
  .donut::after {{ inset:10px; font-size:13px; }}
}}
</style>
</head>
<body>
<h1>Security Report: {escape(repo_short)}</h1>
<div class="header-meta">{escape(repo_full)} | {escape(branch_ref)} | {escape(str(commit_ref)[:8])} | {escape(str(date)[:10])}</div>

<div class="stat-row">
    {stat_cards}
    <div class="donut" aria-label="{total} total findings"></div>
</div>

<div class="tabs">
    <div class="tab active" onclick="switchTab('findings',this)">Findings <span class="tab-badge">{len(non_sca)}</span></div>
    <div class="tab" onclick="switchTab('deps',this)">Dependencies <span class="tab-badge">{len(sca_findings)}</span></div>
    <div class="tab" onclick="switchTab('tools',this)">Tools <span class="tab-badge">{len(tool_sev)}</span></div>
</div>

<div class="tab-panel active" id="panel-findings">
    <div class="filter-bar">
        <div class="filter-row"><span class="filter-label">Severity:</span> {sev_chips}</div>
        <div class="filter-row"><span class="filter-label">Source:</span> {source_chips}</div>
        <div class="filter-row"><span class="filter-label">Triage:</span> {triage_chips}</div>
    </div>
    <div class="counter" id="counter">Showing {len(non_sca)} of {total} findings</div>
    {finding_cards}
</div>

<div class="tab-panel" id="panel-deps">
    {sca_section if sca_section else '<p style="color:#8b949e;padding:16px 0">No dependency vulnerabilities found.</p>'}
</div>

<div class="tab-panel" id="panel-tools">
    {tools_section}
</div>

<div class="footer">Generated by RHOAI Security Audit | {" | ".join(footer_parts)}</div>

<script>
window.switchTab = function(name, el) {{
  document.querySelectorAll('.tab-panel').forEach(function(p) {{ p.classList.remove('active'); }});
  document.querySelectorAll('.tab').forEach(function(t) {{ t.classList.remove('active'); }});
  document.getElementById('panel-' + name).classList.add('active');
  el.classList.add('active');
}};
(function() {{
  var filters = {{}};
  document.querySelectorAll('.filter-chip').forEach(function(chip) {{
    var group = chip.dataset.filter;
    var val = chip.dataset.value;
    if (!filters[group]) filters[group] = {{}};
    filters[group][val] = chip.classList.contains('active');
  }});

  window.toggleFilter = function(chip) {{
    chip.classList.toggle('active');
    var group = chip.dataset.filter;
    var val = chip.dataset.value;
    filters[group][val] = chip.classList.contains('active');
    applyFilters();
  }};

  function applyFilters() {{
    var cards = document.querySelectorAll('.finding-card');
    var shown = 0;
    cards.forEach(function(card) {{
      var sevMatch = !filters.severity || Object.keys(filters.severity).length === 0 || filters.severity[card.dataset.severity];
      var srcMatch = !filters.source || Object.keys(filters.source).length === 0 || filters.source[card.dataset.source];
      var triMatch = !filters.triage || Object.keys(filters.triage).length === 0 || filters.triage[card.dataset.triage];
      if (sevMatch && srcMatch && triMatch) {{
        card.classList.remove('hidden');
        shown++;
      }} else {{
        card.classList.add('hidden');
      }}
    }});
    document.getElementById('counter').textContent = 'Showing ' + shown + ' of {total} findings';
  }}

  applyFilters();
}})();
</script>
</body>
</html>'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_dirs", nargs="+")
    args = parser.parse_args()
    print(generate_html(args.scan_dirs))


if __name__ == "__main__":
    main()
