#!/usr/bin/env python3
"""Shared utilities for all report generators.

Consolidates load_findings, load_metadata, shorten_path, github_url,
AI finding parser, and common constants into a single module.
"""
import json
import re
from collections import Counter
from pathlib import Path

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEV_COLORS = {
    "critical": "#dc3545", "high": "#fd7e14", "medium": "#ffc107",
    "low": "#17a2b8", "info": "#6c757d",
}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SOURCE_COLORS = {
    "adversarial-review": "#2563eb", "semantic-scan": "#7c3aed",
}
TRIAGE_BADGES_HTML = {
    "corroborated": '<span class="chip" style="background:#16a34a;margin-left:4px" title="Found by both SAST and AI">CORR</span>',
    "ai-only": '<span class="chip" style="background:#2563eb;margin-left:4px" title="AI-only finding">AI</span>',
    "sast-only": "",
}

_CONTAINER_PATH_RE = re.compile(r"^/tmp/scan-[^/]+/")


def load_findings(scan_dir):
    """Load triaged (preferred), deduplicated, or normalized findings."""
    p = Path(scan_dir)
    for name in ["triaged-findings.json", "deduplicated-findings.json", "normalized-findings.json"]:
        f = p / name
        if f.exists():
            return json.loads(f.read_text())
    return []


def load_metadata(scan_dir):
    """Load scan metadata with full fallback chain."""
    p = Path(scan_dir)
    meta = {}
    f = p / "scan-metadata.json"
    if f.exists():
        meta = json.loads(f.read_text())
    ss = p / "raw" / "security-summary.json"
    if ss.exists() and not meta.get("repo"):
        try:
            summary = json.loads(ss.read_text())
            meta.setdefault("repo", summary.get("repo", ""))
            meta.setdefault("date", summary.get("scan_date", ""))
            meta.setdefault("findings", summary.get("findings", {}))
        except Exception:
            pass
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
                meta.setdefault("repo", parts[i + 1])
                break
    if not meta.get("date"):
        for part in Path(scan_dir).resolve().parts:
            if len(part) >= 10 and part[4] == "-" and part[7] == "-":
                meta["date"] = part[:10]
                break
    return meta


def shorten_path(filepath, repo_name=""):
    """Normalize file path for display, stripping container and repo prefixes."""
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
            return "/".join(parts[i + 2:]) if i + 2 < len(parts) else filepath
    return filepath


def github_url(filepath, line_start, line_end, repo_full, ref):
    """Build a GitHub permalink URL."""
    if not repo_full or not filepath:
        return ""
    url_path = filepath
    parts = filepath.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p in ("repo", "repos"):
            url_path = "/".join(parts[i + 2:]) if i + 2 < len(parts) else filepath
            break
    try:
        line_start = int(line_start) if line_start else 0
    except (ValueError, TypeError):
        line_start = 0
    try:
        line_end = int(line_end) if line_end else 0
    except (ValueError, TypeError):
        line_end = 0
    frag = f"#L{line_start}" if line_start else ""
    if line_end and line_end != line_start and line_start:
        frag = f"#L{line_start}-L{line_end}"
    return f"https://github.com/{repo_full}/blob/{ref}/{url_path}{frag}"


def github_link_md(filepath, repo_full, branch="main", line=None):
    """Build a markdown GitHub link."""
    clean = shorten_path(filepath, repo_full)
    if not clean or not repo_full:
        return f"`{clean}:{line}`" if line else f"`{clean}`"
    url = f"https://github.com/{repo_full}/blob/{branch}/{clean}"
    if line and str(line).isdigit() and int(line) > 0:
        url += f"#L{line}"
    display = f"{clean}:{line}" if line else clean
    return f"[`{display}`]({url})"


def file_display(filepath, line_start):
    """Format file path for display with line number."""
    parts = filepath.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p in ("repo", "repos"):
            filepath = "/".join(parts[i + 2:]) if i + 2 < len(parts) else filepath
            break
    return f"{filepath}:{line_start}" if line_start else filepath


def get_triage_status(f):
    """Safely extract triage status from a finding."""
    t = f.get("triage", "sast-only")
    if isinstance(t, dict):
        return t.get("status", "sast-only")
    return t if isinstance(t, str) else "sast-only"


def get_origin(f):
    """Safely extract origin from a finding."""
    o = f.get("origin", "sast")
    if isinstance(o, dict):
        return o.get("type", "sast")
    return o if isinstance(o, str) else "sast"


def parse_ai_findings(scan_dir):
    """Parse AI review findings from raw adversarial-review and semantic-scan directories."""
    p = Path(scan_dir)
    ai_findings = []
    for subdir in ["raw/adversarial-reviewing", "raw/adversarial-review", "raw/semantic-scan"]:
        d = p / subdir
        if not d.exists():
            continue
        source = "adversarial-review" if "adversarial" in subdir else "semantic-scan"
        for md_file in sorted(d.glob("*.md")):
            if md_file.name.startswith("."):
                continue
            text = md_file.read_text()
            parsed = _parse_ai_md(text, source)
            ai_findings.extend(parsed)
    return ai_findings


def _parse_ai_md(text, source):
    """Parse AI markdown into findings, handling 3 output formats."""
    findings = []

    # Format 1: "Finding ID: SEC-001" or "### SEC-001"
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
        f["rule_id"] = f["id"]
        file_match = re.search(r'File:\s*`?([^\n`]+)`?', block)
        f["file"] = file_match.group(1).strip() if file_match else ""
        line_match = re.search(r'Lines?:\s*(\d+)', block)
        f["line_start"] = int(line_match.group(1)) if line_match else 0
        f["line_end"] = f["line_start"]
        evidence_match = re.search(r'Evidence:\s*(.+?)(?=\n(?:Impact|Recommended|Finding ID:|\Z))', block, re.DOTALL)
        f["description"] = evidence_match.group(1).strip()[:800] if evidence_match else ""
        fix_match = re.search(r'Recommended fix:\s*(.+?)(?=\n(?:Finding ID:|\Z))', block, re.DOTALL)
        f["recommendation"] = fix_match.group(1).strip()[:800] if fix_match else ""
        snippet_match = re.search(r'```[a-z]*\n(.*?)```', block, re.DOTALL)
        f["snippet"] = snippet_match.group(1).strip()[:500] if snippet_match else ""
        f["confidence"] = 0.7
        f["triage"] = {}
        findings.append(f)

    # Format 2: "## [CRITICAL] Title" or "### [HIGH] Title"
    if not findings:
        blocks = re.split(r'\n(?=##[#]?\s+\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\])', text)
        for i, block in enumerate(blocks):
            heading = re.match(r'##[#]?\s+\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s+(.+?)(?:\n|$)', block)
            if not heading:
                continue
            sev = heading.group(1).lower()
            title = heading.group(2).strip()
            prefix = "SEC" if source == "adversarial-review" else "SCAN"
            fid = f"{prefix}-{i+1:03d}"
            f = {"id": fid, "source": source, "origin": "ai", "category": "ai-review",
                 "detected_by": [source], "title": title, "severity": sev, "rule_id": fid}
            loc_match = re.search(r'(?:- )?\*\*Location\*\*:\s*`?([^`\n]+)`?', block)
            if loc_match:
                raw = loc_match.group(1).strip().split(",")[0].split("(")[0].strip()
                f["file"] = raw
            else:
                f["file"] = ""
            line_match = re.search(r':(\d+)', f.get("file", ""))
            if line_match:
                f["line_start"] = int(line_match.group(1))
                f["file"] = f["file"].split(":")[0]
            else:
                f["line_start"] = 0
            f["line_end"] = f["line_start"]
            desc_match = re.search(
                r'\*\*Description\*\*:?\s*\n?(.*?)(?=\n\*\*(?:Impact|Evidence|Recommendation|Data Flow)|---|\Z)',
                block, re.DOTALL | re.IGNORECASE)
            f["description"] = desc_match.group(1).strip()[:800] if desc_match else ""
            snippet_match = re.search(r'```[a-z]*\n(.*?)```', block, re.DOTALL)
            f["snippet"] = snippet_match.group(1).strip()[:500] if snippet_match else ""
            rec_match = re.search(
                r'\*\*Recommendation\*\*:?\s*\n?(.*?)(?=\n---|\n##|\Z)',
                block, re.DOTALL | re.IGNORECASE)
            f["recommendation"] = rec_match.group(1).strip()[:800] if rec_match else ""
            f["confidence"] = 0.8
            f["triage"] = {}
            findings.append(f)

    # Format 3: "### N. Title" with **Severity**: HIGH
    if not findings:
        blocks = re.split(r'\n(?=### \d+\.)', text)
        for i, block in enumerate(blocks):
            heading = re.match(r'### \d+\.\s+(.+?)(?:\n|$)', block)
            if not heading:
                continue
            f = {"id": f"SCAN-{i+1:03d}", "source": source, "origin": "ai",
                 "category": "ai-review", "detected_by": [source],
                 "title": heading.group(1).strip(), "rule_id": f"SCAN-{i+1:03d}"}
            sev_match = re.search(r'\*\*Severity\*\*:\s*(\w+)', block, re.IGNORECASE)
            sev = sev_match.group(1).lower() if sev_match else "medium"
            f["severity"] = {"critical": "critical", "high": "high",
                             "medium": "medium", "low": "low"}.get(sev, "medium")
            file_match = re.search(r'\*\*(?:File|Location)\*\*:\s*`?([^`\n]+)`?', block)
            if file_match:
                raw = file_match.group(1).strip().split(",")[0].split("(")[0].strip()
                f["file"] = raw
            else:
                f["file"] = ""
            line_match = re.search(r':(\d+)', f.get("file", ""))
            if line_match:
                f["line_start"] = int(line_match.group(1))
                f["file"] = f["file"].split(":")[0]
            else:
                f["line_start"] = 0
            f["line_end"] = f["line_start"]
            desc_match = re.search(r'(?:Description|Impact|Details).*?:\s*(.+?)(?=\n\*\*|\n###|\Z)',
                                   block, re.DOTALL | re.IGNORECASE)
            f["description"] = desc_match.group(1).strip()[:800] if desc_match else ""
            snippet_match = re.search(r'```[a-z]*\n(.*?)```', block, re.DOTALL)
            f["snippet"] = snippet_match.group(1).strip()[:500] if snippet_match else ""
            rec_match = re.search(r'(?:Remediation|Fix|Recommendation).*?:\s*(.+?)(?=\n###|\Z)',
                                  block, re.DOTALL | re.IGNORECASE)
            f["recommendation"] = rec_match.group(1).strip()[:800] if rec_match else ""
            f["confidence"] = 0.7
            f["triage"] = {}
            findings.append(f)

    return findings
