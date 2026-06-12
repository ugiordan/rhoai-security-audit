#!/usr/bin/env python3
"""Generate consolidated security reports.

Single repo: detailed per-tool breakdown with CVE section
Multi repo:  aggregation matrix + per-repo summaries

Usage:
    python3 report.py <scan-dir>              # single repo
    python3 report.py <scan-dir1> <scan-dir2> # multi repo
    python3 report.py <scan-dir> --full       # include all severities
"""
import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from report_common import load_findings, load_metadata, shorten_path, github_link_md as github_link


def _severity_badge(sev):
    icons = {"critical": "!!!", "high": "!!", "medium": "!", "low": ".", "info": ""}
    return icons.get(sev, "")


def generate_single_report(findings, metadata, full=False):
    lines = []
    repo = metadata.get("repo", "Unknown")
    date = metadata.get("date", "Unknown")
    branch = metadata.get("branch", "main")
    commit = metadata.get("commit", "unknown")[:8]
    repo_short = repo.split("/")[-1] if "/" in repo else repo

    def _link(f):
        return github_link(f["file"], repo, branch, f.get("line_start"))

    sev_counts = Counter(f["severity"] for f in findings)
    tool_counts = Counter()
    category_counts = Counter()
    for f in findings:
        for t in f.get("detected_by", [f.get("source", "unknown")]):
            tool_counts[t] += 1
        category_counts[f.get("category", "other")] += 1

    # Header
    lines.append("> **CONFIDENTIAL** — This report may contain undisclosed security findings. Do not share outside authorized personnel. Do not post in public channels.")
    lines.append("")
    lines.append(f"# Security Report: {repo}")
    lines.append("")
    lines.append(f"**Date:** {date}  ")
    lines.append(f"**Branch:** {branch}  ")
    lines.append(f"**Commit:** {commit}  ")
    lines.append(f"**Tools:** {len(tool_counts)}  ")
    lines.append(f"**AI Skills:** {len(metadata.get('ai_skills_run', []))}  ")
    lines.append("")

    # Executive summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["critical", "high", "medium", "low", "info"]:
        c = sev_counts.get(sev, 0)
        if c > 0 or sev in ("critical", "high"):
            lines.append(f"| {sev} | {c} |")
    lines.append(f"| **Total** | **{len(findings)}** |")
    lines.append("")

    # Tool coverage matrix (tool x severity)
    lines.append("## Tool Coverage")
    lines.append("")
    tool_sev = defaultdict(Counter)
    for f in findings:
        src = f.get("source", "unknown")
        tool_sev[src][f["severity"]] += 1
    tools_sorted = sorted(tool_sev.keys())
    lines.append("| Tool | Critical | High | Medium | Low | Info | Total |")
    lines.append("|------|----------|------|--------|-----|------|-------|")
    for tool in tools_sorted:
        s = tool_sev[tool]
        total = sum(s.values())
        lines.append(f"| {tool} | {s.get('critical',0)} | {s.get('high',0)} | "
                     f"{s.get('medium',0)} | {s.get('low',0)} | {s.get('info',0)} | {total} |")
    lines.append("")

    # Category breakdown
    lines.append("## Finding Categories")
    lines.append("")
    lines.append("| Category | Count | Description |")
    lines.append("|----------|-------|-------------|")
    cat_desc = {
        "secrets": "Hardcoded credentials, API keys, tokens",
        "sca": "Known CVEs in dependencies (trivy, grype, govulncheck)",
        "k8s": "Kubernetes manifest misconfigurations",
        "config": "Dockerfile, shell, YAML, CI/CD misconfigurations",
        "cicd": "GitHub Actions workflow security issues",
        "injection": "Code injection vulnerabilities",
        "other": "General SAST findings (semgrep, gosec)",
    }
    for cat, count in category_counts.most_common():
        desc = cat_desc.get(cat, "")
        lines.append(f"| {cat} | {count} | {desc} |")
    lines.append("")

    # CVE / SCA section
    sca_findings = [f for f in findings if f.get("category") == "sca"]
    if sca_findings:
        lines.append("## Dependency Vulnerabilities (CVEs)")
        lines.append("")
        lines.append(f"**{len(sca_findings)} known vulnerabilities** found in dependencies.")
        lines.append("")

        sca_crit = [f for f in sca_findings if f["severity"] == "critical"]
        sca_high = [f for f in sca_findings if f["severity"] == "high"]

        for sca_sev, sca_list in [("Critical", sca_crit), ("High", sca_high)]:
            if not sca_list:
                continue
            lines.append(f"### {sca_sev} CVEs ({len(sca_list)})")
            lines.append("")
            lines.append("| # | CVE / Advisory | Package | Source | Fix |")
            lines.append("|---|---------------|---------|--------|-----|")
            for i, f in enumerate(sca_list[:30], 1):
                title = f["title"][:60].replace("|", "/")
                flink = _link(f)
                rec = f.get("recommendation", "")[:40].replace("|", "/")
                lines.append(f"| {i} | {title} | {flink} | {f['source']} | {rec} |")
            if len(sca_list) > 30:
                lines.append(f"| ... | +{len(sca_list) - 30} more | | | |")
            lines.append("")

    # Secrets section
    secret_findings = [f for f in findings if f.get("category") == "secrets"]
    if secret_findings:
        lines.append(f"## Secrets Detected ({len(secret_findings)})")
        lines.append("")
        lines.append("| # | Source | File | Description | Verified |")
        lines.append("|---|--------|------|-------------|----------|")
        for i, f in enumerate(secret_findings[:20], 1):
            flink = _link(f)
            title = f["title"][:50].replace("|", "/")
            verified = "yes" if f.get("confidence", 0) > 0.9 else "no"
            lines.append(f"| {i} | {f['source']} | {flink} | {title} | {verified} |")
        if len(secret_findings) > 20:
            lines.append(f"| ... | +{len(secret_findings) - 20} more | | | |")
        lines.append("")

    # Critical + High SAST findings (non-SCA, non-secrets)
    for sev in ["critical", "high"]:
        sev_findings = [f for f in findings
                        if f["severity"] == sev
                        and f.get("category") not in ("sca", "secrets")]
        if sev_findings:
            lines.append(f"## {sev.title()} SAST Findings ({len(sev_findings)})")
            lines.append("")
            lines.append("| # | Tool | File | Title | Detected By |")
            lines.append("|---|------|------|-------|-------------|")
            for i, f in enumerate(sev_findings[:50], 1):
                detected = ", ".join(f.get("detected_by", [f.get("source", "")]))
                title = f["title"][:55].replace("|", "/")
                flink = _link(f)
                lines.append(f"| {i} | {f['source']} | {flink} | {title} | {detected} |")
            if len(sev_findings) > 50:
                lines.append(f"| ... | | | | +{len(sev_findings) - 50} more | |")
            lines.append("")

    # Full report: medium/low/info
    if full:
        for sev in ["medium", "low", "info"]:
            sev_findings = [f for f in findings if f["severity"] == sev]
            if sev_findings:
                lines.append(f"## {sev.title()} Findings ({len(sev_findings)})")
                lines.append("")
                lines.append("| # | Tool | File | Title |")
                lines.append("|---|------|------|-------|")
                for i, f in enumerate(sev_findings[:30], 1):
                    flink = _link(f)
                    lines.append(f"| {i} | {f['source']} | {flink} | {f['title'][:55].replace('|','/')} |")
                if len(sev_findings) > 30:
                    lines.append(f"| ... | | | | +{len(sev_findings) - 30} more |")
                lines.append("")

    # Recommendations
    lines.append("## Recommendations")
    lines.append("")
    recs = [f for f in findings
            if f.get("recommendation", "").strip()
            and f["severity"] in ("critical", "high")]
    seen = set()
    n = 0
    for f in recs:
        rec = f["recommendation"].strip().replace("\n", " ")[:120]
        if rec and rec not in seen and len(rec) > 5:
            n += 1
            seen.add(rec)
            lines.append(f"{n}. **{f['title'][:55]}**: {rec}")
            if n >= 10:
                break
    if n == 0:
        lines.append("No specific recommendations from tool output.")
    lines.append("")
    lines.append("---")
    lines.append("*Generated by RHOAI Security Audit*")

    return "\n".join(lines)


def generate_multi_report(scan_dirs, full=False):
    lines = []
    all_data = []
    for d in scan_dirs:
        findings = load_findings(d)
        metadata = load_metadata(d)
        if findings or metadata:
            all_data.append((d, findings, metadata))

    if not all_data:
        return "No scan data found."

    lines.append("# RHOAI Security Audit Report")
    lines.append("")
    lines.append(f"**Date:** {all_data[0][2].get('date', 'Unknown')}  ")
    lines.append(f"**Repos scanned:** {len(all_data)}  ")
    total = sum(len(f) for _, f, _ in all_data)
    lines.append(f"**Total findings:** {total}  ")
    lines.append("")

    # Aggregation matrix: repo x tool
    all_tools = set()
    repo_tool_counts = {}
    for _, findings, metadata in all_data:
        repo = metadata.get("repo", "Unknown")
        tool_counts = Counter()
        for f in findings:
            src = f.get("source", "unknown")
            tool_counts[src] += 1
            all_tools.add(src)
        repo_tool_counts[repo] = tool_counts

    tools_sorted = sorted(all_tools)

    lines.append("## Findings by Repo and Tool")
    lines.append("")
    header = "| Repo | " + " | ".join(tools_sorted) + " | Total |"
    sep = "|------|" + "|".join(["---:" for _ in tools_sorted]) + "|------:|"
    lines.append(header)
    lines.append(sep)

    for repo, tc in sorted(repo_tool_counts.items()):
        repo_short = repo.split("/")[-1] if "/" in repo else repo
        cells = [str(tc.get(t, 0)) for t in tools_sorted]
        total_repo = sum(tc.values())
        lines.append(f"| {repo_short} | " + " | ".join(cells) + f" | {total_repo} |")
    lines.append("")

    # Severity summary across all repos
    lines.append("## Severity Summary")
    lines.append("")
    lines.append("| Repo | Critical | High | Medium | Low | Info | Total |")
    lines.append("|------|----------|------|--------|-----|------|-------|")
    for _, findings, metadata in all_data:
        repo = metadata.get("repo", "Unknown")
        repo_short = repo.split("/")[-1] if "/" in repo else repo
        sev = Counter(f["severity"] for f in findings)
        lines.append(f"| {repo_short} | {sev.get('critical',0)} | {sev.get('high',0)} | "
                     f"{sev.get('medium',0)} | {sev.get('low',0)} | {sev.get('info',0)} | {len(findings)} |")
    lines.append("")

    # CVE summary across repos
    all_sca = []
    for _, findings, metadata in all_data:
        repo = metadata.get("repo", "Unknown")
        for f in findings:
            if f.get("category") == "sca":
                f_copy = dict(f)
                f_copy["_repo"] = repo
                all_sca.append(f_copy)

    if all_sca:
        lines.append(f"## Dependency Vulnerabilities ({len(all_sca)} total)")
        lines.append("")
        sca_by_repo = Counter(f["_repo"] for f in all_sca)
        lines.append("| Repo | CVE Count |")
        lines.append("|------|-----------|")
        for repo, count in sca_by_repo.most_common():
            repo_short = repo.split("/")[-1] if "/" in repo else repo
            lines.append(f"| {repo_short} | {count} |")
        lines.append("")

        crit_sca = [f for f in all_sca if f["severity"] == "critical"]
        if crit_sca:
            lines.append(f"### Critical CVEs ({len(crit_sca)})")
            lines.append("")
            lines.append("| # | Repo | CVE / Advisory | Package | Source |")
            lines.append("|---|------|---------------|---------|--------|")
            for i, f in enumerate(crit_sca[:30], 1):
                repo_short = f["_repo"].split("/")[-1]
                title = f["title"][:50].replace("|", "/")
                lines.append(f"| {i} | {repo_short} | {title} | {f['file'][:30]} | {f['source']} |")
            lines.append("")

    # Per-repo details
    for scan_dir, findings, metadata in all_data:
        repo = metadata.get("repo", "Unknown")
        lines.append(f"## {repo}")
        lines.append("")
        sev = Counter(f["severity"] for f in findings)
        lines.append(f"Critical: {sev.get('critical',0)} | "
                     f"High: {sev.get('high',0)} | "
                     f"Medium: {sev.get('medium',0)} | "
                     f"Low: {sev.get('low',0)} | "
                     f"Info: {sev.get('info',0)}")
        lines.append("")

        crits = [f for f in findings if f["severity"] == "critical"]
        if crits:
            lines.append("**Critical findings:**")
            for f in crits[:10]:
                flink = github_link(f["file"], repo, branch="main", line=f.get("line_start"))
                lines.append(f"- [{f['source']}] {flink}: {f['title'][:60]}")
            if len(crits) > 10:
                lines.append(f"- +{len(crits) - 10} more")
            lines.append("")

    lines.append("---")
    lines.append("*Generated by RHOAI Security Audit*")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_dirs", nargs="+")
    parser.add_argument("--full", action="store_true")
    args = parser.parse_args()

    if len(args.scan_dirs) == 1:
        findings = load_findings(args.scan_dirs[0])
        metadata = load_metadata(args.scan_dirs[0])
        print(generate_single_report(findings, metadata, full=args.full))
    else:
        print(generate_multi_report(args.scan_dirs, full=args.full))


if __name__ == "__main__":
    main()
