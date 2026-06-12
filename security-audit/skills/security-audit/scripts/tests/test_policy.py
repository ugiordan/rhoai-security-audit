"""Tests for dynamic OpenShell policy generation."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline import _generate_openshell_policy


def test_policy_anthropic():
    policy = _generate_openshell_policy("anthropic/claude-sonnet-4-6")
    assert "api.anthropic.com" in policy


def test_policy_openai():
    policy = _generate_openshell_policy("openai/gpt-4o")
    assert "api.openai.com" in policy


def test_policy_google():
    policy = _generate_openshell_policy("google/gemini-2.5-pro")
    assert "generativelanguage.googleapis.com" in policy


def test_policy_none_defaults_anthropic():
    policy = _generate_openshell_policy(None)
    assert "api.anthropic.com" in policy


def test_policy_unknown_provider_uses_env():
    from unittest.mock import patch
    with patch.dict(os.environ, {"SECURITY_AUDIT_PROVIDER_HOST": "my-api.example.com"}):
        policy = _generate_openshell_policy("custom/model")
        assert "my-api.example.com" in policy


def test_policy_unknown_provider_no_env_raises():
    import pytest
    from unittest.mock import patch
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(SystemExit):
            _generate_openshell_policy("custom/model")
