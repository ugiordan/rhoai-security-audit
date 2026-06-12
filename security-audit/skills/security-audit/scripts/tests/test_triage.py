"""Tests for triage.py: keyword caching and cross-correlation."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from triage import cross_correlate, _title_keywords, _file_key


def _sast(id, file, title="shell injection", desc=""):
    return {
        "id": id, "file": file, "title": title, "description": desc,
        "severity": "high", "origin": "sast", "triage": {},
    }


def _ai(id, file, title="shell injection vulnerability", desc=""):
    return {
        "id": id, "file": file, "title": title, "description": desc,
        "severity": "high", "origin": "ai", "triage": {},
    }


def test_corroboration_same_file_matching_keywords():
    sast = [_sast("S1", "pkg/auth/handler.go", "shell injection in handler")]
    ai = [_ai("A1", "pkg/auth/handler.go", "shell injection vulnerability in handler")]
    cross_correlate(sast, ai)
    assert ai[0]["triage"]["status"] == "corroborated"
    assert sast[0]["triage"].get("corroborated_by_ai") == "A1"


def test_no_corroboration_different_files():
    sast = [_sast("S1", "pkg/auth/handler.go", "shell injection")]
    ai = [_ai("A1", "cmd/main.go", "shell injection")]
    cross_correlate(sast, ai)
    assert ai[0]["triage"]["status"] == "ai-only"
    assert sast[0]["triage"]["status"] == "sast-only"


def test_no_corroboration_different_topics():
    sast = [_sast("S1", "pkg/auth/handler.go", "SQL injection database query")]
    ai = [_ai("A1", "pkg/auth/handler.go", "race condition mutex lock")]
    cross_correlate(sast, ai)
    assert ai[0]["triage"]["status"] == "ai-only"


def test_sast_only_when_no_ai():
    sast = [_sast("S1", "a.go"), _sast("S2", "b.go")]
    cross_correlate(sast, [])
    assert sast[0]["triage"]["status"] == "sast-only"
    assert sast[1]["triage"]["status"] == "sast-only"


def test_ai_only_when_no_sast():
    ai = [_ai("A1", "a.go")]
    cross_correlate([], ai)
    assert ai[0]["triage"]["status"] == "ai-only"


def test_empty_inputs():
    cross_correlate([], [])


def test_title_keywords_strips_stopwords():
    kw = _title_keywords("the shell injection in handler")
    assert "the" not in kw
    assert "shell" in kw
    assert "injection" in kw
    assert "handler" in kw


def test_title_keywords_ignores_short_words():
    kw = _title_keywords("XSS in URL via ID")
    assert "XSS" not in kw  # uppercase gets lowered
    assert "xss" in kw
    assert "url" in kw
    assert "via" in kw
    assert "in" not in kw


def test_file_key_strips_repo_prefix():
    assert "internal/controller/main.go" in _file_key("repos/myrepo/internal/controller/main.go")


def test_file_key_short_path():
    key = _file_key("main.go")
    assert key == "main.go"


def test_multiple_sast_best_match():
    sast = [
        _sast("S1", "pkg/auth/handler.go", "unrelated config issue"),
        _sast("S2", "pkg/auth/handler.go", "shell injection command execution vulnerability"),
    ]
    ai = [_ai("A1", "pkg/auth/handler.go", "shell injection command execution")]
    cross_correlate(sast, ai)
    assert ai[0]["triage"]["status"] == "corroborated"
    assert ai[0]["triage"]["corroborated_by"] == "S2"


def test_large_input_completes():
    """Verify keyword caching handles 500 SAST x 50 AI without timeout."""
    sast = [_sast(f"S{i}", f"file{i % 100}.go", f"issue {i} vulnerability injection security") for i in range(500)]
    ai = [_ai(f"A{i}", f"file{i % 100}.go", f"issue {i} vulnerability injection security found") for i in range(50)]
    cross_correlate(sast, ai)
    corr = sum(1 for f in ai if f["triage"]["status"] == "corroborated")
    assert corr > 0


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
