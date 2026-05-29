#!/usr/bin/env python3
"""Deduplicate security findings across tools."""
import json
import sys

COMPATIBLE_CATEGORIES = {
    frozenset({"secrets", "crypto"}),
    frozenset({"config", "k8s"}),
}

def categories_compatible(a, b):
    if a == b:
        return True
    pair = frozenset({a, b})
    return any(pair <= group for group in COMPATIBLE_CATEGORIES)


def lines_overlap(a, b, threshold=5):
    a_start, a_end = a.get("line_start", 0), a.get("line_end", 0) or a.get("line_start", 0)
    b_start, b_end = b.get("line_start", 0), b.get("line_end", 0) or b.get("line_start", 0)
    if a_start == 0 and b_start == 0:
        return False
    return abs(a_start - b_start) <= threshold or abs(a_end - b_end) <= threshold


def merge_findings(primary, duplicate):
    sev_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    merged = dict(primary)
    if sev_rank.get(duplicate["severity"], 0) > sev_rank.get(primary["severity"], 0):
        merged["severity"] = duplicate["severity"]
    sources = list(set(primary.get("detected_by", []) + duplicate.get("detected_by", [])))
    merged["detected_by"] = sorted(sources)
    if len(duplicate.get("description", "")) > len(primary.get("description", "")):
        merged["description"] = duplicate["description"]
    if not merged.get("recommendation") and duplicate.get("recommendation"):
        merged["recommendation"] = duplicate["recommendation"]
    merged["confidence"] = max(primary.get("confidence", 0), duplicate.get("confidence", 0))
    return merged


def deduplicate(findings):
    """Deduplicate findings by grouping on file path first (O(n*k) instead of O(n^2))."""
    from collections import defaultdict

    by_file = defaultdict(list)
    no_file = []
    for i, f in enumerate(findings):
        fpath = f.get("file", "")
        if fpath:
            by_file[fpath].append((i, f))
        else:
            no_file.append((i, f))

    merged = []
    used = set()

    for fpath, group in by_file.items():
        for idx_a, (i, a) in enumerate(group):
            if i in used:
                continue
            current = dict(a)
            for j, b in group[idx_a + 1:]:
                if j in used:
                    continue
                if (lines_overlap(a, b)
                    and categories_compatible(a.get("category", ""), b.get("category", ""))):
                    current = merge_findings(current, b)
                    used.add(j)
            merged.append(current)

    for i, f in no_file:
        if i not in used:
            merged.append(dict(f))

    return merged


def main():
    if len(sys.argv) < 2:
        print("Usage: dedup.py <normalized-findings.json>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1]) as f:
        findings = json.load(f)

    json.dump(deduplicate(findings), sys.stdout, indent=2)


if __name__ == "__main__":
    main()
