#!/usr/bin/env python3
"""Generate security report as a MkDocs Material site.

Generates markdown pages + mkdocs.yml, then builds with `mkdocs build`.
Uses the same Material for MkDocs theme as architecture-analyzer and strat-creator:
Red Hat fonts, black primary, dark/light toggle, navigation tabs.

Usage:
    python3 report_html.py <scan-dir>
    python3 report_html.py <scan-dir1> <scan-dir2>

Output: builds site into <scan-dir>/site/ and prints path.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

from report_common import (
    load_findings, load_metadata, shorten_path,
    github_link_md as github_link, get_triage_status as _get_triage,
    get_origin as _get_origin,
)

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_EMOJI = {
    "critical": ":red_circle:",
    "high": ":orange_circle:",
    "medium": ":yellow_circle:",
    "low": ":blue_circle:",
    "info": ":white_circle:",
}




def generate_mkdocs_yml(docs_dir, metadata, repo_full, multi=False):
    repo_short = repo_full.split("/")[-1] if repo_full else "security-report"
    site_name = "RHOAI Security Audit" if multi else f"Security Report: {repo_short}"

    nav_entries = """nav:
  - Overview: index.md
  - Critical & High: critical-high.md
  - All Findings: all-findings.md
  - Dependencies: dependencies.md
  - Tool Coverage: tools.md"""

    yml = f"""site_name: "{site_name}"
repo_url: https://github.com/{repo_full}
repo_name: {repo_full}
use_directory_urls: false

copyright: Copyright &copy; Red Hat, Inc.

theme:
  name: material
  language: en
  icon:
    repo: fontawesome/brands/github
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
    - search.suggest
    - search.highlight
    - content.code.copy
    - content.tabs.link
    - toc.follow

plugins:
  - search

markdown_extensions:
  - admonition
  - pymdownx.details
  - pymdownx.superfences:
      custom_fences:
        - name: mermaid
          class: mermaid
          format: !!python/name:pymdownx.superfences.fence_code_format
  - pymdownx.highlight:
      anchor_linenums: true
  - pymdownx.inlinehilite
  - pymdownx.tabbed:
      alternate_style: true
  - pymdownx.emoji:
      emoji_index: !!python/name:material.extensions.emoji.twemoji
      emoji_generator: !!python/name:material.extensions.emoji.to_svg
  - attr_list
  - md_in_html
  - tables
  - toc:
      permalink: true
  - pymdownx.tasklist:
      custom_checkbox: true

extra_css:
  - custom.css

extra_javascript:
  - filters.js

{nav_entries}
"""
    (Path(docs_dir).parent / "mkdocs.yml").write_text(yml)

    css = """\
/* Hide empty header rows in metadata tables */
.md-typeset table:not([class]) thead th:empty { display: none; }
.md-typeset table:not([class]) thead:has(th:empty) { display: none; }

/* Filter chips */
.filter-bar { display:flex; gap:6px; flex-wrap:wrap; margin:12px 0; padding:8px 0; border-bottom:1px solid var(--md-default-fg-color--lightest); }
.filter-chip { display:inline-block; padding:3px 10px; border-radius:12px; font-size:11px; font-weight:600; cursor:pointer; border:1px solid var(--md-default-fg-color--lightest); color:var(--md-default-fg-color--light); background:transparent; transition:all .15s; }
.filter-chip:hover { border-color:var(--md-accent-fg-color); color:var(--md-accent-fg-color); }
.filter-chip.active { color:#fff; border-color:transparent; }
.filter-chip[data-sev="critical"].active { background:#dc3545; }
.filter-chip[data-sev="high"].active { background:#fd7e14; }
.filter-chip[data-sev="medium"].active { background:#ffc107; color:#000; }
.filter-chip[data-sev="low"].active { background:#17a2b8; }
.filter-chip[data-sev="info"].active { background:#6c757d; }
.filter-chip[data-triage="corroborated"].active { background:#16a34a; }
.filter-chip[data-triage="ai-only"].active { background:#2563eb; }
.filter-chip[data-triage="sast-only"].active { background:#6c757d; }
.finding-filtered { display:none !important; }

/* Enhanced finding cards */
.finding-badges { display:inline-flex; gap:4px; margin-left:6px; }
.finding-badges .badge { font-size:9px; padding:1px 6px; border-radius:8px; font-weight:600; color:#fff; }
.badge-corr { background:#16a34a; }
.badge-ai { background:#2563eb; }
.badge-conf-high { background:#166534; }
.badge-conf-med { background:#854d0e; }
.badge-conf-low { background:#991b1b; }
"""
    (Path(docs_dir) / "custom.css").write_text(css)

    js = """\
document.addEventListener('DOMContentLoaded', function() {
  var chips = document.querySelectorAll('.filter-chip');
  chips.forEach(function(chip) {
    chip.addEventListener('click', function() {
      chip.classList.toggle('active');
      applyFilters();
    });
  });
});
function applyFilters() {
  var activeSevsEls = document.querySelectorAll('.filter-chip[data-sev].active');
  var activeTriageEls = document.querySelectorAll('.filter-chip[data-triage].active');
  var activeSevs = Array.from(activeSevsEls).map(function(e) { return e.dataset.sev; });
  var activeTriages = Array.from(activeTriageEls).map(function(e) { return e.dataset.triage; });
  var findings = document.querySelectorAll('[data-finding-sev]');
  findings.forEach(function(f) {
    var sev = f.dataset.findingSev;
    var triage = f.dataset.findingTriage || '';
    var sevMatch = activeSevs.length === 0 || activeSevs.indexOf(sev) >= 0;
    var triageMatch = activeTriages.length === 0 || activeTriages.indexOf(triage) >= 0;
    if (sevMatch && triageMatch) {
      f.classList.remove('finding-filtered');
    } else {
      f.classList.add('finding-filtered');
    }
  });
}
"""
    (Path(docs_dir) / "filters.js").write_text(js)


def generate_index(findings, metadata, repo_full, branch):
    total = len(findings)
    sev_counts = Counter(f["severity"] for f in findings)
    non_sca = [f for f in findings if f.get("category") != "sca"]
    non_sca_sev = Counter(f["severity"] for f in non_sca)
    tool_counts = Counter(f.get("source", "unknown") for f in findings)
    triage_counts = Counter(_get_triage(f) for f in findings)
    cat_counts = Counter(f.get("category", "other") for f in findings)
    repo_short = repo_full.split("/")[-1] if repo_full else "unknown"
    commit = str(metadata.get("commit", ""))[:8]
    scan_date = str(metadata.get("date", ""))

    cat_labels = {
        "secrets": "Secrets", "sca": "Dependencies (CVE/SCA)", "k8s": "Kubernetes",
        "config": "Configuration", "cicd": "CI/CD", "injection": "Injection", "other": "SAST",
    }

    # Severity summary table
    sev_table = "| Severity | Count |\n|----------|-------|\n"
    for s in SEV_ORDER:
        c = sev_counts.get(s, 0)
        if c > 0:
            sev_table += f"| **{s.upper()}** | {c} |\n"
    sev_table += f"| **TOTAL** | **{total}** |\n"

    # Tool table
    tool_table = "| Tool | Findings |\n|------|----------|\n"
    for tool, cnt in tool_counts.most_common():
        tool_table += f"| {tool} | {cnt} |\n"

    # Category table
    cat_table = "| Category | Count |\n|----------|-------|\n"
    for cat, cnt in cat_counts.most_common():
        cat_table += f"| {cat_labels.get(cat, cat)} | {cnt} |\n"

    # Triage summary
    corr = triage_counts.get("corroborated", 0)
    ai_only = triage_counts.get("ai-only", 0)
    sast_only = triage_counts.get("sast-only", 0)

    # Must-fix count
    must_fix = sev_counts.get("critical", 0) + sev_counts.get("high", 0)

    return f"""---
hide:
  - navigation
---

!!! danger "CONFIDENTIAL"
    This report may contain undisclosed security findings. Do not share outside authorized personnel. Do not post in public channels.

# Security Report: {repo_short}

| | |
|---|---|
| **Repository** | [{repo_full}](https://github.com/{repo_full}) |
| **Branch** | [`{branch}`](https://github.com/{repo_full}/tree/{branch}) |
| **Commit** | [`{commit}`](https://github.com/{repo_full}/commit/{commit}) |
| **Scan Date** | {scan_date} |
| **Tools** | {len(tool_counts)} |
| **Total Findings** | {total} |

---

## Summary

<div class="grid cards" markdown>

-   :material-alert-circle: **[{sev_counts.get("critical", 0)} Critical](critical-high.html#critical)**

    ---

    Immediate action required

-   :material-alert: **[{sev_counts.get("high", 0)} High](critical-high.html#high)**

    ---

    Fix before next release

-   :material-alert-outline: **[{sev_counts.get("medium", 0)} Medium](all-findings.html#medium-{non_sca_sev.get("medium", 0)})**

    ---

    Address in upcoming sprint

-   :material-information: **[{sev_counts.get("low", 0) + sev_counts.get("info", 0)} Low/Info](all-findings.html#low-{non_sca_sev.get("low", 0)})**

    ---

    Track for future cleanup

</div>

!!! danger "Must-Fix Items: {must_fix}"
    {must_fix} findings at **HIGH** or above require immediate attention.
    See [Critical & High findings](critical-high.html) for details.

## Severity Breakdown

{sev_table}

## Triage Summary

| Triage Status | Count | Description |
|---------------|-------|-------------|
| :material-check-decagram: **Corroborated** | {corr} | Independently confirmed by both SAST tools and AI review |
| :material-brain: **AI-only** | {ai_only} | Found by AI review only, requires manual verification |
| **SAST-only** | {sast_only} | Found by traditional SAST tools only |

## Categories

{cat_table}

## Tools

{tool_table}

## About This Report

This report was generated by the **RHOAI Security Audit** pipeline:

1. **SAST Scan**: {len(tool_counts)} tools (semgrep, trivy, grype, osv-scanner, kube-linter, zizmor, and others) scan the repository for known vulnerabilities, misconfigurations, and code patterns.
2. **AI Review**: Adversarial multi-agent review (5 specialist agents: SEC, PERF, QUAL, CORR, ARCH) and semantic security analysis identify logic flaws, race conditions, and design-level issues that SAST tools cannot detect.
3. **Triage**: Findings from both sources are cross-correlated. Issues found by both SAST and AI are marked as **corroborated** (highest confidence). AI-only findings are flagged for manual review.

**Triage badges:**

- :material-check-decagram: **CORROBORATED**: found independently by both SAST tools and AI review
- :material-brain: **AI-only**: found by AI review only (logic/semantic issue)
- No badge: found by SAST tools only

---

*Generated by RHOAI Security Audit*
"""


def _filter_chips_html(findings):
    """Generate filter chip HTML for a findings page."""
    from collections import Counter
    sev_counts = Counter(f["severity"] for f in findings)
    triage_counts = Counter(
        _get_triage(f) for f in findings
    )

    chips = '<div class="filter-bar">\n'
    for sev in SEV_ORDER:
        c = sev_counts.get(sev, 0)
        if c > 0:
            chips += f'  <span class="filter-chip" data-sev="{sev}">{sev.upper()} ({c})</span>\n'
    for triage, label in [("corroborated", "CORR"), ("ai-only", "AI"), ("sast-only", "SAST")]:
        c = triage_counts.get(triage, 0)
        if c > 0:
            chips += f'  <span class="filter-chip" data-triage="{triage}">{label} ({c})</span>\n'
    chips += '</div>\n\n'
    return chips


def generate_critical_high(findings, repo_full, branch):
    crit = [f for f in findings if f["severity"] == "critical"]
    high = [f for f in findings if f["severity"] == "high"]
    combined = crit + high

    md = "# Critical & High Findings\n\n"
    md += f"**{len(crit)} Critical** and **{len(high)} High** findings requiring immediate action.\n\n"

    if combined:
        md += _filter_chips_html(combined)

    if crit:
        md += "## Critical\n\n"
        for f in crit:
            md += _finding_block(f, repo_full, branch)

    if high:
        md += "## High\n\n"
        for f in high:
            md += _finding_block(f, repo_full, branch)

    if not crit and not high:
        md += "!!! success \"No critical or high findings\"\n    All clear.\n"

    return md


def generate_all_findings(findings, repo_full, branch):
    md = "# All Findings\n\n"
    md += f"**{len(findings)} total findings** across all severity levels.\n\n"

    non_cve = [f for f in findings if f.get("category") != "sca"]

    md += _filter_chips_html(non_cve)

    by_sev = defaultdict(list)
    for f in non_cve:
        by_sev[f["severity"]].append(f)

    for sev in SEV_ORDER:
        group = by_sev.get(sev, [])
        if not group:
            continue
        md += f"## {sev.title()} ({len(group)})\n\n"
        for f in group:
            md += _finding_block(f, repo_full, branch)

    return md


def generate_dependencies(findings, repo_full, branch):
    cves = [f for f in findings if f.get("category") == "sca"]

    md = "# Dependency Vulnerabilities\n\n"

    if not cves:
        md += "!!! success \"No dependency vulnerabilities found\"\n"
        return md

    md += f"**{len(cves)} CVEs** found in project dependencies.\n\n"
    md += "| Severity | Tool | Package/File | Title | Fix |\n"
    md += "|----------|------|-------------|-------|-----|\n"

    for f in cves:
        sev = f["severity"].upper()
        tool = f.get("source", "")
        file_link = github_link(f.get("file", ""), repo_full, branch)
        title = f.get("title", "")[:70]
        rec = f.get("recommendation", "")[:50]
        md += f"| **{sev}** | {tool} | {file_link} | {title} | {rec} |\n"

    return md


def generate_tools(findings, metadata=None):
    AI_SOURCES = {"adversarial-review", "semantic-scan"}

    tool_sev = defaultdict(Counter)
    for f in findings:
        tool_sev[f.get("source", "unknown")][f["severity"]] += 1

    # Add tools that ran but produced zero findings
    if metadata:
        meta_findings = metadata.get("findings", {})
        for tk in meta_findings:
            tn = tk.replace("_", "-")
            if tn not in tool_sev:
                tool_sev[tn] = Counter()

    sast_tools = {k: v for k, v in tool_sev.items() if k not in AI_SOURCES}
    ai_tools = {k: v for k, v in tool_sev.items() if k in AI_SOURCES}

    sast_count = len(sast_tools)
    ai_count = len(ai_tools)

    md = "# Tool Coverage\n\n"
    md += f"**{sast_count} SAST tools** and **{ai_count} AI skills** executed during this scan.\n\n"

    # Split SAST tools into those with findings and those without
    sast_with = {k: v for k, v in sast_tools.items() if sum(v.values()) > 0}
    sast_clean = sorted(k for k, v in sast_tools.items() if sum(v.values()) == 0)

    # SAST section: tools with findings
    md += "## SAST Tools\n\n"
    md += "Static analysis tools scanning for known vulnerabilities, misconfigurations, and code patterns.\n\n"

    if sast_with:
        md += "### Findings\n\n"
        md += "| Tool | Critical | High | Medium | Low | Info | Total |\n"
        md += "|------|----------|------|--------|-----|------|-------|\n"

        sast_totals = Counter()
        for tool in sorted(sast_with):
            s = sast_with[tool]
            t = sum(s.values())
            cells = " | ".join(str(s.get(sv, 0) or "") for sv in SEV_ORDER)
            md += f"| **{tool}** | {cells} | **{t}** |\n"
            sast_totals.update(s)

        sast_total_cells = " | ".join(str(sast_totals.get(sv, 0)) for sv in SEV_ORDER)
        md += f"| **Total** | {sast_total_cells} | **{sum(sast_totals.values())}** |\n"
        md += "\n"

    if sast_clean:
        md += f"### Clean ({len(sast_clean)} tools, no findings)\n\n"
        md += ", ".join(f"**{t}**" for t in sast_clean) + "\n\n"

    # AI section
    if ai_tools:
        # Triage stats for AI findings
        ai_findings = [f for f in findings if f.get("source", "") in AI_SOURCES]
        ai_triage = Counter(
            f.get("triage", {}).get("status", "ai-only") if isinstance(f.get("triage"), dict) else "ai-only"
            for f in ai_findings
        )
        corr = ai_triage.get("corroborated", 0)
        ai_only = ai_triage.get("ai-only", 0)

        md += "## AI Skills\n\n"
        md += "Multi-agent AI review identifying logic flaws, race conditions, and design-level issues beyond pattern matching.\n\n"
        md += "| Skill | Critical | High | Medium | Low | Info | Total |\n"
        md += "|-------|----------|------|--------|-----|------|-------|\n"

        ai_totals = Counter()
        for tool in sorted(ai_tools):
            s = ai_tools[tool]
            t = sum(s.values())
            cells = " | ".join(str(s.get(sv, 0) or "") for sv in SEV_ORDER)
            md += f"| **{tool}** | {cells} | **{t}** |\n"
            ai_totals.update(s)

        ai_total_cells = " | ".join(str(ai_totals.get(sv, 0)) for sv in SEV_ORDER)
        md += f"| **AI Total** | {ai_total_cells} | **{sum(ai_totals.values())}** |\n"
        md += "\n"

        md += "### Triage Quality\n\n"
        md += "| Metric | Count | Description |\n"
        md += "|--------|-------|-------------|\n"
        md += f"| :material-check-decagram: Corroborated | **{corr}** | Independently confirmed by both SAST and AI |\n"
        md += f"| :material-brain: AI-only | **{ai_only}** | Found by AI only, requires manual review |\n"
        if corr + ai_only > 0:
            rate = round(corr / (corr + ai_only) * 100)
            md += f"| Corroboration rate | **{rate}%** | Higher = more overlap with SAST tools |\n"
        md += "\n"

    return md


def _split_description(desc):
    """Split a description blob into prose, impact, and evidence sections."""
    import re as _re
    prose = desc
    impact = ""
    evidence = ""

    # Try splitting on "- Impact:" or "**Impact**:" patterns
    impact_match = _re.search(r'[-*]*\s*\*?\*?Impact\*?\*?:\s*', desc, _re.IGNORECASE)
    if impact_match:
        prose = desc[:impact_match.start()].strip()
        rest = desc[impact_match.end():]
        # Check if evidence follows
        evidence_match = _re.search(r'[-*]*\s*\*?\*?Evidence\*?\*?:\s*', rest, _re.IGNORECASE)
        if evidence_match:
            impact = rest[:evidence_match.start()].strip()
            evidence = rest[evidence_match.end():].strip()
        else:
            impact = rest.strip()
    else:
        # Try splitting on "- Evidence:" alone
        evidence_match = _re.search(r'[-*]*\s*\*?\*?Evidence\*?\*?:\s*', desc, _re.IGNORECASE)
        if evidence_match:
            prose = desc[:evidence_match.start()].strip()
            evidence = desc[evidence_match.end():].strip()

    # Also split on "Remediation:" if present
    rem = ""
    for section in [prose, impact]:
        rem_match = _re.search(r'[-*]*\s*\*?\*?Remediation\*?\*?:\s*', section, _re.IGNORECASE)
        if rem_match:
            rem = section[rem_match.end():].strip()
            if section == prose:
                prose = section[:rem_match.start()].strip()
            else:
                impact = section[:rem_match.start()].strip()
            break

    # Clean up leading dashes/bullets
    prose = _re.sub(r'^[-•]\s*', '', prose).strip()
    impact = _re.sub(r'^[-•]\s*', '', impact).strip()
    evidence = _re.sub(r'^[-•]\s*', '', evidence).strip()

    return prose, impact, evidence, rem


def _finding_block(f, repo_full, branch):
    sev = f["severity"]
    source = f.get("source", "unknown")
    title = f.get("title", "untitled")
    desc = f.get("description", "")
    file_link = github_link(f.get("file", ""), repo_full, branch, f.get("line_start"))
    snippet = f.get("snippet", "")
    rec = f.get("recommendation", "")
    triage = _get_triage(f)
    origin = _get_origin(f)

    admon_type = {
        "critical": "danger",
        "high": "warning",
        "medium": "note",
        "low": "info",
        "info": "tip",
    }.get(sev, "note")

    triage_row = ""
    if origin == "ai" and triage == "corroborated":
        triage_row = "    | **Triage** | :material-check-decagram: **CORROBORATED** (confirmed by both SAST and AI) |\n"
    elif origin == "ai":
        triage_row = "    | **Triage** | :material-brain: **AI-only** (found by AI review only) |\n"

    confidence_row = ""
    if origin == "ai":
        conf_val = float(f.get("confidence", 0))
        if conf_val >= 0.8:
            confidence_row = "    | **Confidence** | :material-shield-check: **HIGH** (code-verified, multi-agent confirmed) |\n"
        elif conf_val >= 0.6:
            confidence_row = "    | **Confidence** | :material-shield-alert: **MEDIUM** (plausible, not fully verified) |\n"
        else:
            confidence_row = "    | **Confidence** | :material-shield-off: **LOW** (speculative or challenged) |\n"

    # Inline badges for triage and confidence
    badges = ""
    if origin == "ai" and triage == "corroborated":
        badges += '<span class="badge badge-corr">CORR</span>'
    elif origin == "ai":
        badges += '<span class="badge badge-ai">AI</span>'
    if origin == "ai":
        conf_val = float(f.get("confidence", 0))
        if conf_val >= 0.8:
            badges += '<span class="badge badge-conf-high">HIGH conf</span>'
        elif conf_val >= 0.6:
            badges += '<span class="badge badge-conf-med">MED conf</span>'
        elif conf_val > 0:
            badges += '<span class="badge badge-conf-low">LOW conf</span>'

    badge_html = f' <span class="finding-badges">{badges}</span>' if badges else ""

    md = f'<div data-finding-sev="{sev}" data-finding-triage="{triage}" markdown>\n\n'
    md += f'!!! {admon_type} "{title}{badge_html}"\n'
    md += f"\n"
    md += f"    | | |\n"
    md += f"    |:--|:--|\n"
    md += f"    | **Severity** | **{sev.upper()}** |\n"
    md += f"    | **Source** | {source} |\n"
    md += f"    | **File** | {file_link} |\n"
    md += triage_row
    md += confidence_row
    md += f"\n"

    prose, impact, evidence, desc_rem = _split_description(desc)

    if prose:
        md += f"    **Description**\n\n"
        for line in prose.split("\n")[:8]:
            md += f"    {line}\n"
        md += "\n"

    if impact:
        md += f"    **Impact**\n\n"
        for line in impact.split("\n")[:6]:
            md += f"    {line}\n"
        md += "\n"

    if evidence:
        md += f"    **Evidence**\n\n"
        for line in evidence.split("\n")[:6]:
            eline = line.strip()
            if eline.startswith("-"):
                md += f"    {eline}\n"
            else:
                md += f"    - {eline}\n"
        md += "\n"

    if snippet:
        md += "    **Code**\n\n"
        md += "    ```\n"
        for line in snippet.split("\n")[:10]:
            md += f"    {line}\n"
        md += "    ```\n\n"

    final_rec = rec or desc_rem
    if final_rec:
        md += f"    ??? tip \"Remediation\"\n\n"
        for line in final_rec[:800].split("\n")[:12]:
            md += f"        {line}\n"
        md += "\n"

    md += "</div>\n\n"
    return md


def build_site(scan_dirs):
    all_data = []
    for d in scan_dirs:
        findings = load_findings(d)
        metadata = load_metadata(d)
        if findings or metadata:
            all_data.append((d, findings, metadata))

    if not all_data:
        print("No scan data found.")
        return

    # Use first scan dir as output target
    output_base = Path(all_data[0][0])
    mkdocs_root = output_base / "mkdocs-report"
    docs_dir = mkdocs_root / "docs"

    # Clean previous build
    if mkdocs_root.exists():
        shutil.rmtree(mkdocs_root)
    docs_dir.mkdir(parents=True)

    multi = len(all_data) > 1
    all_findings = []
    for _, f, _ in all_data:
        all_findings.extend(f)

    first_meta = all_data[0][2]
    repo_full = first_meta.get("repo", "")
    branch = first_meta.get("branch", "main")

    # Generate mkdocs.yml
    generate_mkdocs_yml(docs_dir, first_meta, repo_full, multi)

    # Generate pages
    (docs_dir / "index.md").write_text(generate_index(all_findings, first_meta, repo_full, branch))
    (docs_dir / "critical-high.md").write_text(generate_critical_high(all_findings, repo_full, branch))
    (docs_dir / "all-findings.md").write_text(generate_all_findings(all_findings, repo_full, branch))
    (docs_dir / "dependencies.md").write_text(generate_dependencies(all_findings, repo_full, branch))
    (docs_dir / "tools.md").write_text(generate_tools(all_findings, first_meta))

    # Build with mkdocs
    site_dir = output_base.resolve() / "security-report-site"
    if site_dir.exists():
        shutil.rmtree(site_dir)
    print(f"Building MkDocs site...")
    result = subprocess.run(
        ["mkdocs", "build", "--strict", "--site-dir", str(site_dir)],
        cwd=str(mkdocs_root),
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        result = subprocess.run(
            ["mkdocs", "build", "--site-dir", str(site_dir)],
            cwd=str(mkdocs_root),
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"mkdocs build failed:\n{result.stderr}")
            return

    site_index = site_dir / "index.html"
    if site_index.exists():
        print(f"Report: file://{site_index.resolve()}")

        # Create zip for sharing
        import zipfile
        zip_path = output_base.resolve() / "security-report-site.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in site_dir.rglob("*"):
                if f.is_file():
                    zf.write(f, f.relative_to(site_dir.parent))
        print(f"Zip: file://{zip_path} ({zip_path.stat().st_size // 1024}KB)")

    # Clean up build temp
    shutil.rmtree(mkdocs_root, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Generate MkDocs Material security report")
    parser.add_argument("scan_dirs", nargs="+", help="Scan output directories")
    args = parser.parse_args()
    build_site(args.scan_dirs)


if __name__ == "__main__":
    main()
