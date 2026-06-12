"""Tests for dedup.py: O(n*k) indexed deduplication."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dedup import deduplicate, lines_overlap, categories_compatible, merge_findings


def _finding(id, file="a.go", line=10, sev="high", cat="other", source="semgrep"):
    return {
        "id": id, "file": file, "line_start": line, "line_end": line,
        "severity": sev, "category": cat, "source": source,
        "title": f"Finding {id}", "description": f"Desc {id}",
        "detected_by": [source], "confidence": 0.8,
    }


def test_no_duplicates():
    findings = [_finding("A", file="a.go", line=10), _finding("B", file="b.go", line=20)]
    result = deduplicate(findings)
    assert len(result) == 2


def test_same_file_same_line_merges():
    findings = [
        _finding("A", file="a.go", line=10, source="semgrep"),
        _finding("B", file="a.go", line=10, source="grype"),
    ]
    result = deduplicate(findings)
    assert len(result) == 1
    assert set(result[0]["detected_by"]) == {"grype", "semgrep"}


def test_same_file_distant_lines_no_merge():
    findings = [
        _finding("A", file="a.go", line=10),
        _finding("B", file="a.go", line=100),
    ]
    result = deduplicate(findings)
    assert len(result) == 2


def test_same_file_within_threshold_merges():
    findings = [
        _finding("A", file="a.go", line=10),
        _finding("B", file="a.go", line=14),
    ]
    result = deduplicate(findings)
    assert len(result) == 1


def test_different_files_no_merge():
    findings = [
        _finding("A", file="a.go", line=10),
        _finding("B", file="b.go", line=10),
    ]
    result = deduplicate(findings)
    assert len(result) == 2


def test_incompatible_categories_no_merge():
    findings = [
        _finding("A", file="a.go", line=10, cat="secrets"),
        _finding("B", file="a.go", line=10, cat="cicd"),
    ]
    result = deduplicate(findings)
    assert len(result) == 2


def test_compatible_categories_merge():
    findings = [
        _finding("A", file="a.go", line=10, cat="config"),
        _finding("B", file="a.go", line=10, cat="k8s"),
    ]
    result = deduplicate(findings)
    assert len(result) == 1


def test_no_file_findings_preserved():
    findings = [
        _finding("A", file="", line=0),
        _finding("B", file="", line=0),
    ]
    result = deduplicate(findings)
    assert len(result) == 2


def test_merge_takes_higher_severity():
    findings = [
        _finding("A", file="a.go", line=10, sev="medium"),
        _finding("B", file="a.go", line=10, sev="critical"),
    ]
    result = deduplicate(findings)
    assert len(result) == 1
    assert result[0]["severity"] == "critical"


def test_three_duplicates_merge_to_one():
    findings = [
        _finding("A", file="a.go", line=10, source="semgrep"),
        _finding("B", file="a.go", line=11, source="grype"),
        _finding("C", file="a.go", line=12, source="trivy"),
    ]
    result = deduplicate(findings)
    assert len(result) == 1
    assert len(result[0]["detected_by"]) == 3


def test_empty_input():
    assert deduplicate([]) == []


def test_single_finding():
    result = deduplicate([_finding("A")])
    assert len(result) == 1


def test_large_input_completes():
    """Verify the indexed approach handles 1000 findings without timeout."""
    findings = [_finding(f"F-{i}", file=f"file{i % 50}.go", line=i % 200) for i in range(1000)]
    result = deduplicate(findings)
    assert len(result) <= 1000
    assert len(result) > 0


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
