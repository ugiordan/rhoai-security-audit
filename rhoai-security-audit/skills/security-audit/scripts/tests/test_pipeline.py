"""Tests for pipeline.py harness detection and model configuration."""
import os
import shutil
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline import detect_harness


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
