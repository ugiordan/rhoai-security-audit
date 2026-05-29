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

_CONTAINER_PATH_RE = re.compile(r"^/tmp/scan-[^/]+/")

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_EMOJI = {
    "critical": ":red_circle:",
    "high": ":orange_circle:",
    "medium": ":yellow_circle:",
    "low": ":blue_circle:",
    "info": ":white_circle:",
}


def _get_triage(f):
    t = f.get("triage", "sast-only")
    if isinstance(t, dict):
        return t.get("status", "sast-only")
    return t if isinstance(t, str) else "sast-only"


def _get_origin(f):
    o = f.get("origin", "sast")
    if isinstance(o, dict):
        return o.get("type", "sast")
    return o if isinstance(o, str) else "sast"


def load_findings(scan_dir):
    p = Path(scan_dir)
    for name in ["triaged-findings.json", "deduplicated-findings.json", "normalized-findings.json"]:
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
    filepath = filepath.replace("\\", "/")
    filepath = _CONTAINER_PATH_RE.sub("", filepath)
    filepath = filepath.lstrip("/")
    parts = filepath.split("/")
    if repo_name:
        short = repo_name.split("/")[-1] if "/" in repo_name else repo_name
        if parts and parts[0] == short:
            return "/".join(parts[1:])
        if parts and parts[0] == f"scan-{short}":
            return "/".join(parts[1:])
    for i, p in enumerate(parts):
        if p in ("repo", "repos"):
            return "/".join(parts[i + 1:]) if i + 1 < len(parts) else filepath
    return filepath


def github_link(filepath, repo_full, branch="main", line=None):
    clean = shorten_path(filepath, repo_full)
    if not clean or not repo_full:
        return f"`{clean}:{line}`" if line else f"`{clean}`"
    url = f"https://github.com/{repo_full}/blob/{branch}/{clean}"
    if line and str(line).isdigit() and int(line) > 0:
        url += f"#L{line}"
    display = f"{clean}:{line}" if line else clean
    return f"[`{display}`]({url})"


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

{nav_entries}
"""
    (Path(docs_dir).parent / "mkdocs.yml").write_text(yml)


def generate_index(findings, metadata, repo_full, branch):
    total = len(findings)
    sev_counts = Counter(f["severity"] for f in findings)
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
| **Branch** | `{branch}` |
| **Commit** | `{commit}` |
| **Scan Date** | {scan_date} |
| **Tools** | {len(tool_counts)} |
| **Total Findings** | {total} |

---

## Summary

<div class="grid cards" markdown>

-   :material-alert-circle: **{sev_counts.get("critical", 0)} Critical**

    ---

    Immediate action required

-   :material-alert: **{sev_counts.get("high", 0)} High**

    ---

    Fix before next release

-   :material-alert-outline: **{sev_counts.get("medium", 0)} Medium**

    ---

    Address in upcoming sprint

-   :material-information: **{sev_counts.get("low", 0) + sev_counts.get("info", 0)} Low/Info**

    ---

    Track for future cleanup

</div>

!!! danger "Must-Fix Items: {must_fix}"
    {must_fix} findings at **HIGH** or above require immediate attention.
    See [Critical & High findings](critical-high.md) for details.

## Severity Breakdown

{sev_table}

## Triage Summary

| Triage Status | Count | Description |
|---------------|-------|-------------|
| :green_circle: Corroborated | {corr} | Found by both SAST tools and AI analysis |
| :blue_circle: AI-only | {ai_only} | Found by AI semantic analysis only |
| :white_circle: SAST-only | {sast_only} | Found by traditional SAST tools only |

## Categories

{cat_table}

## Tools

{tool_table}

---

*Generated by RHOAI Security Audit*
"""


def generate_critical_high(findings, repo_full, branch):
    crit = [f for f in findings if f["severity"] == "critical"]
    high = [f for f in findings if f["severity"] == "high"]

    md = "# Critical & High Findings\n\n"
    md += f"**{len(crit)} Critical** and **{len(high)} High** findings requiring immediate action.\n\n"

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


def generate_tools(findings):
    tool_sev = defaultdict(Counter)
    for f in findings:
        tool_sev[f.get("source", "unknown")][f["severity"]] += 1

    md = "# Tool Coverage\n\n"
    md += "## Findings by Tool and Severity\n\n"
    md += "| Tool | Critical | High | Medium | Low | Info | Total |\n"
    md += "|------|----------|------|--------|-----|------|-------|\n"

    for tool in sorted(tool_sev):
        s = tool_sev[tool]
        t = sum(s.values())
        cells = " | ".join(str(s.get(sv, 0) or "") for sv in SEV_ORDER)
        md += f"| **{tool}** | {cells} | **{t}** |\n"

    # Total row
    totals = Counter()
    for s in tool_sev.values():
        totals.update(s)
    total_cells = " | ".join(str(totals.get(sv, 0)) for sv in SEV_ORDER)
    md += f"| **TOTAL** | {total_cells} | **{sum(totals.values())}** |\n"

    return md


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

    # Admonition type based on severity
    admon_type = {
        "critical": "danger",
        "high": "warning",
        "medium": "note",
        "low": "info",
        "info": "tip",
    }.get(sev, "note")

    # Triage badge
    triage_badge = ""
    if origin == "ai" and triage == "corroborated":
        triage_badge = " :green_circle: CORROBORATED"
    elif origin == "ai":
        triage_badge = " :blue_circle: AI"

    md = f'!!! {admon_type} "{sev.upper()}: {title}"{triage_badge}\n'
    md += f"    **Source:** {source} | **File:** {file_link}\n\n"

    if desc:
        for line in desc.split("\n")[:8]:
            md += f"    {line}\n"
        md += "\n"

    if snippet:
        md += "    ```\n"
        for line in snippet.split("\n")[:10]:
            md += f"    {line}\n"
        md += "    ```\n\n"

    if rec:
        md += f"    **Remediation:** {rec[:300]}\n\n"

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
    (docs_dir / "tools.md").write_text(generate_tools(all_findings))

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
