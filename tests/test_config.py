"""Tests for QIP config module."""
import pytest
from pathlib import Path
from qip.config import Settings


def test_default_settings():
    s = Settings()
    assert s.severity_threshold == "medium"
    assert s.review_port == 8500
    assert "grype" in s.scanners


def test_settings_override():
    s = Settings(severity_threshold="critical", max_patches=5)
    assert s.severity_threshold == "critical"
    assert s.max_patches == 5
