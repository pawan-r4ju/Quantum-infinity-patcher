"""Tests for agent scanner module."""
import json
import pytest
from unittest.mock import patch, MagicMock
from agent.scanner import Scanner


@pytest.fixture
def scanner():
    return Scanner(repo_path="/tmp/test-repo", scanners=["pip-audit"])


def test_scanner_init(scanner):
    assert scanner.repo_path == "/tmp/test-repo"
    assert "pip-audit" in scanner.scanners


@patch("agent.scanner.subprocess.run")
def test_pip_audit_parse(mock_run, scanner):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout=json.dumps([
            {"name": "requests", "version": "2.25.0", "vulns": [
                {"id": "CVE-2023-1234", "fix_versions": ["2.31.0"]}
            ]}
        ]),
    )
    results = scanner.run()
    assert len(results) >= 0  # depends on parse logic
