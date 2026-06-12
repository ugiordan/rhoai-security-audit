"""Tests for pipeline.py harness detection, model configuration, and command building."""
import os
import shutil
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline import detect_harness, resolve_model, _build_ai_command


def test_detect_harness_explicit_override_claude():
    with patch.dict(os.environ, {"SECURITY_AUDIT_HARNESS": "claude"}, clear=False):
        assert detect_harness() == "claude"


def test_detect_harness_explicit_override_opencode():
    with patch.dict(os.environ, {"SECURITY_AUDIT_HARNESS": "opencode"}, clear=False):
        assert detect_harness() == "opencode"


def test_detect_harness_claude_skill_dir():
    env = {"CLAUDE_SKILL_DIR": "/some/path", "SECURITY_AUDIT_HARNESS": ""}
    with patch.dict(os.environ, env, clear=False):
        assert detect_harness() == "claude"


def test_detect_harness_prefers_claude_over_opencode():
    """When both binaries exist, Claude Code wins (backward compat)."""
    with patch.dict(os.environ, {"SECURITY_AUDIT_HARNESS": "", "CLAUDE_SKILL_DIR": ""}, clear=False):
        with patch.object(shutil, "which", side_effect=lambda x: "/usr/bin/claude" if x == "claude" else None):
            assert detect_harness() == "claude"


def test_detect_harness_no_harness_exits():
    """When nothing is installed, fail loudly."""
    with patch.dict(os.environ, {"SECURITY_AUDIT_HARNESS": "", "CLAUDE_SKILL_DIR": ""}, clear=False):
        with patch.object(shutil, "which", return_value=None):
            with pytest.raises(SystemExit):
                detect_harness()


# --- resolve_model tests ---

def test_resolve_model_cli_flag():
    assert resolve_model("anthropic/claude-sonnet-4-6") == "anthropic/claude-sonnet-4-6"


def test_resolve_model_env_var():
    with patch.dict(os.environ, {"SECURITY_AUDIT_MODEL": "openai/gpt-4o"}, clear=False):
        assert resolve_model(None) == "openai/gpt-4o"


def test_resolve_model_cli_overrides_env():
    with patch.dict(os.environ, {"SECURITY_AUDIT_MODEL": "openai/gpt-4o"}, clear=False):
        assert resolve_model("anthropic/claude-sonnet-4-6") == "anthropic/claude-sonnet-4-6"


def test_resolve_model_none():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("SECURITY_AUDIT_MODEL", None)
        assert resolve_model(None) is None


# --- _build_ai_command tests ---

def test_build_claude_command():
    cmd = _build_ai_command("claude", "test prompt", model=None)
    assert cmd[0] == "claude"
    assert "-p" in cmd
    assert "--allowedTools" in cmd


def test_build_opencode_command():
    cmd = _build_ai_command("opencode", "test prompt", model="anthropic/claude-sonnet-4-6")
    assert cmd[0] == "opencode"
    assert "run" in cmd
    assert "--model" in cmd
    assert "anthropic/claude-sonnet-4-6" in cmd


def test_build_opencode_command_no_model():
    cmd = _build_ai_command("opencode", "test prompt", model=None)
    assert "--model" not in cmd


def test_build_unknown_harness():
    with pytest.raises(ValueError, match="Unknown harness"):
        _build_ai_command("unknown", "test prompt")
