#!/usr/bin/env python3
"""Triage security findings by cross-correlating SAST and AI review results.

Reads deduplicated SAST findings + AI review markdown outputs.
Produces a single triaged-findings.json with:
- Corroborated findings (found by both SAST and AI): highest confidence
- AI-only findings (code logic bugs SAST can't detect): high confidence
- SAST-only findings: standard confidence
- Noise-demoted findings (templates, examples): lowered priority

Usage:
    python3 triage.py <scan-dir> > triaged-findings.json
"""
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path


NOISE_PATHS = {"scripts/templates/", "examples/", "testdata/", "test/", "demos/"}

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def load_sast_findings(scan_dir):
    p = Path(scan_dir)
    for name in ["deduplicated-findings.json", "normalized-findings.json"]:
        fpath = p / name
        if fpath.exists():
            findings = json.loads(fpath.read_text())
            for finding in findings:
                finding["origin"] = "sast"
                finding.setdefault("triage", {})
            return findings
    return []


def parse_ai_findings(scan_dir):
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
            findings = _extract_findings(text, source)
            ai_findings.extend(findings)
    return ai_findings


def _extract_findings(text, source):
    findings = []

    # Try adversarial-reviewing format: "Finding ID: SEC-001" or "### SEC-001"
    blocks = re.split(r'\n(?=(?:Finding ID:|###?\s+(?:SEC|PERF|QUAL|CORR|ARCH|FINDING)-\d+))', text)
    for block in blocks:
        id_match = re.search(
            r'(?:Finding ID:\s*|###?\s+)((?:SEC|PERF|QUAL|CORR|ARCH|FINDING)-\d+)', block)
        if not id_match:
            continue
        f = _parse_adversarial_block(block, id_match.group(1), source)
        if f:
            findings.append(f)

    # Try bracket-severity format: "## [CRITICAL] Title" or "### [HIGH] Title"
    if not findings:
        blocks = re.split(r'\n(?=##[#]?\s+\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\])', text)
        for i, block in enumerate(blocks):
            heading = re.match(
                r'##[#]?\s+\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s+(.+?)(?:\n|$)', block)
            if not heading:
                continue
            f = _parse_bracket_block(block, heading.group(2).strip(),
                                     heading.group(1).lower(), source, i + 1)
            if f:
                findings.append(f)

    # Try semantic-scan format: "### N. Title" with **Severity**: HIGH
    if not findings:
        blocks = re.split(r'\n(?=### \d+\.)', text)
        for i, block in enumerate(blocks):
            heading = re.match(r'### \d+\.\s+(.+?)(?:\n|$)', block)
            if not heading:
                continue
            f = _parse_semantic_block(block, heading.group(1).strip(), source, i + 1)
            if f:
                findings.append(f)

    return findings


def _parse_adversarial_block(block, finding_id, source):
    f = {"id": finding_id, "source": source, "origin": "ai",
         "category": "ai-review", "detected_by": [source], "triage": {}}

    sev_match = re.search(r'Severity:\s*(\w+)', block, re.IGNORECASE)
    if sev_match:
        sev = sev_match.group(1).lower()
        f["severity"] = {"critical": "critical", "important": "high", "high": "high",
                         "medium": "medium", "minor": "low"}.get(sev, "medium")
    else:
        f["severity"] = "medium"

    title_match = re.search(r'Title:\s*(.+?)(?:\n|$)', block)
    f["title"] = title_match.group(1).strip() if title_match else f["id"]
    f["rule_id"] = f["id"]

    file_match = re.search(r'File:\s*`?([^\n`]+)`?', block)
    f["file"] = file_match.group(1).strip() if file_match else ""

    line_match = re.search(r'Lines?:\s*(\d+)', block)
    f["line_start"] = int(line_match.group(1)) if line_match else 0
    f["line_end"] = f["line_start"]

    evidence_match = re.search(
        r'Evidence:\s*(.+?)(?=\n(?:Impact|Recommended|Finding ID:|\Z))', block, re.DOTALL)
    f["description"] = evidence_match.group(1).strip()[:500] if evidence_match else ""

    fix_match = re.search(
        r'Recommended fix:\s*(.+?)(?=\n(?:Finding ID:|\Z))', block, re.DOTALL)
    f["recommendation"] = fix_match.group(1).strip()[:300] if fix_match else ""

    conf_match = re.search(r'Confidence:\s*(\w+)', block, re.IGNORECASE)
    f["confidence"] = {"high": 0.9, "medium": 0.7, "low": 0.5}.get(
        conf_match.group(1).lower() if conf_match else "medium", 0.7)

    return f


def _parse_bracket_block(block, title, severity, source, index):
    """Parse bracket-severity format: ## [CRITICAL] Title with **Field**: value and markdown sections."""
    prefix = "SEC" if source == "adversarial-review" else "SCAN"
    fid = f"{prefix}-{index:03d}"
    f = {"id": fid, "source": source, "origin": "ai",
         "category": "ai-review", "detected_by": [source], "triage": {},
         "title": title, "rule_id": fid, "severity": severity}

    loc_match = re.search(r'\*\*Location\*\*:\s*`?([^`\n]+)`?', block)
    if not loc_match:
        loc_match = re.search(r'- \*\*Location\*\*:\s*`?([^`\n]+)`?', block)
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
    f["description"] = desc_match.group(1).strip()[:500] if desc_match else ""

    impact_match = re.search(
        r'\*\*Impact\*\*:?\s*\n?(.*?)(?=\n\*\*(?:Evidence|Recommendation)|---|\Z)',
        block, re.DOTALL | re.IGNORECASE)
    if impact_match and not f["description"]:
        f["description"] = impact_match.group(1).strip()[:500]

    snippet_match = re.search(r'```[a-z]*\n(.*?)```', block, re.DOTALL)
    f["snippet"] = snippet_match.group(1).strip()[:500] if snippet_match else ""

    rec_match = re.search(
        r'\*\*Recommendation\*\*:?\s*\n?(.*?)(?=\n---|\n##|\Z)',
        block, re.DOTALL | re.IGNORECASE)
    f["recommendation"] = rec_match.group(1).strip()[:300] if rec_match else ""

    f["confidence"] = 0.8

    return f


def _parse_semantic_block(block, title, source, index):
    """Parse semantic-scan format: ### N. Title with **Field**: value."""
    f = {"id": f"SCAN-{index:03d}", "source": source, "origin": "ai",
         "category": "ai-review", "detected_by": [source], "triage": {},
         "title": title, "rule_id": f"SCAN-{index:03d}"}

    sev_match = re.search(r'\*\*Severity\*\*:\s*(\w+)', block, re.IGNORECASE)
    if sev_match:
        sev = sev_match.group(1).lower()
        f["severity"] = {"critical": "critical", "high": "high",
                         "medium": "medium", "low": "low"}.get(sev, "medium")
    else:
        f["severity"] = "medium"

    file_match = re.search(r'\*\*File\*\*:\s*`?([^`\n]+)`?', block)
    if file_match:
        raw = file_match.group(1).strip()
        f["file"] = raw.split(",")[0].split("(")[0].strip()

    line_match = re.search(r':(\d+)', f.get("file", ""))
    if line_match:
        f["line_start"] = int(line_match.group(1))
        f["file"] = f["file"].split(":")[0]
    else:
        f["line_start"] = 0
    f["line_end"] = f["line_start"]

    conf_match = re.search(r'\*\*Confidence\*\*:\s*([\d.]+)', block)
    f["confidence"] = float(conf_match.group(1)) if conf_match else 0.7

    desc_match = re.search(r'(?:Description|Impact|Details).*?:\s*(.+?)(?=\n\*\*|\n###|\Z)', block, re.DOTALL | re.IGNORECASE)
    f["description"] = desc_match.group(1).strip()[:500] if desc_match else ""

    fix_match = re.search(r'(?:Remediation|Fix|Recommendation).*?:\s*(.+?)(?=\n###|\Z)', block, re.DOTALL | re.IGNORECASE)
    f["recommendation"] = fix_match.group(1).strip()[:300] if fix_match else ""

    return f


def _file_key(filepath):
    """Normalize file path for matching."""
    parts = filepath.replace("\\", "/").strip().split("/")
    for i, p in enumerate(parts):
        if p in ("repo", "repos", "cmd", "pkg", "internal", "api"):
            return "/".join(parts[i:])
    return "/".join(parts[-3:]) if len(parts) > 3 else "/".join(parts)


def _title_keywords(title):
    """Extract keywords from a finding title for fuzzy matching."""
    stopwords = {"the", "a", "an", "in", "of", "for", "to", "is", "and", "or", "not", "with"}
    words = set(re.findall(r'[a-zA-Z]{3,}', title.lower())) - stopwords
    return words


def cross_correlate(sast_findings, ai_findings):
    """Match AI findings to SAST findings on same file + overlapping topic."""
    sast_by_file = defaultdict(list)
    for f in sast_findings:
        key = _file_key(f.get("file", ""))
        if key:
            sast_by_file[key].append(f)

    # Pre-compute keywords for all SAST findings
    sast_kw_cache = {}
    for f in sast_findings:
        fid = id(f)
        sast_kw_cache[fid] = _title_keywords(
            f.get("title", "") + " " + f.get("description", ""))

    corroborated_sast_ids = set()

    for ai_f in ai_findings:
        ai_file = _file_key(ai_f.get("file", ""))
        ai_keywords = _title_keywords(ai_f.get("title", "") + " " + ai_f.get("description", ""))
        best_match = None
        best_score = 0

        for sast_file, sast_list in sast_by_file.items():
            if not ai_file or ai_file not in sast_file and sast_file not in ai_file:
                continue
            for sast_f in sast_list:
                sast_keywords = sast_kw_cache[id(sast_f)]
                overlap = len(ai_keywords & sast_keywords)
                if overlap >= 2 and overlap > best_score:
                    best_match = sast_f
                    best_score = overlap

        if best_match:
            ai_f["triage"]["status"] = "corroborated"
            ai_f["triage"]["corroborated_by"] = best_match.get("id", "")
            ai_f["triage"]["match_score"] = best_score
            corroborated_sast_ids.add(best_match.get("id", ""))
            best_match.setdefault("triage", {})
            best_match["triage"]["corroborated_by_ai"] = ai_f["id"]
        else:
            ai_f["triage"]["status"] = "ai-only"

    for f in sast_findings:
        if f.get("id") not in corroborated_sast_ids:
            f["triage"]["status"] = "sast-only"

    return corroborated_sast_ids


def demote_noise(findings):
    """Lower priority for findings in non-production paths."""
    for f in findings:
        filepath = f.get("file", "")
        for noise in NOISE_PATHS:
            if noise in filepath:
                original_sev = f["severity"]
                if SEV_RANK.get(original_sev, 0) > SEV_RANK["low"]:
                    f["triage"]["demoted_from"] = original_sev
                    f["triage"]["demote_reason"] = f"Finding in {noise.rstrip('/')} (non-production code)"
                    f["severity"] = "low"
                break


def compute_triage_confidence(findings):
    """Set confidence scores based on triage status."""
    for f in findings:
        status = f.get("triage", {}).get("status", "")
        base = f.get("confidence", 0.7)
        if isinstance(base, str):
            base = {"high": 0.9, "medium": 0.7, "low": 0.5}.get(base, 0.7)

        if status == "corroborated":
            f["confidence"] = min(base + 0.15, 1.0)
        elif status == "ai-only" and f.get("origin") == "ai":
            f["confidence"] = base
        elif status == "sast-only":
            f["confidence"] = base
        elif f.get("triage", {}).get("demoted_from"):
            f["confidence"] = max(base - 0.2, 0.3)


def triage(scan_dir):
    sast = load_sast_findings(scan_dir)
    ai = parse_ai_findings(scan_dir)

    cross_correlate(sast, ai)
    demote_noise(sast)
    demote_noise(ai)

    merged = sast + ai
    compute_triage_confidence(merged)

    merged.sort(key=lambda f: (
        -SEV_RANK.get(f["severity"], 0),
        -f.get("confidence", 0.5),
        f.get("file", ""),
    ))

    stats = {
        "total": len(merged),
        "sast_only": sum(1 for f in merged if f.get("triage", {}).get("status") == "sast-only"),
        "ai_only": sum(1 for f in merged if f.get("triage", {}).get("status") == "ai-only"),
        "corroborated": sum(1 for f in merged if f.get("triage", {}).get("status") == "corroborated"),
        "demoted": sum(1 for f in merged if f.get("triage", {}).get("demoted_from")),
    }
    print(json.dumps(stats), file=sys.stderr)

    return merged


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Triage security findings")
    parser.add_argument("scan_dir", help="Scan output directory")
    args = parser.parse_args()

    findings = triage(args.scan_dir)
    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
