"""Tests for deduplicator module."""
from agent.deduplicator import Deduplicator


def test_dedup_removes_duplicates():
    findings = [
        {"cve_id": "CVE-2023-001", "component": "foo", "version": "1.0"},
        {"cve_id": "CVE-2023-001", "component": "foo", "version": "1.0"},
        {"cve_id": "CVE-2023-002", "component": "bar", "version": "2.0"},
    ]
    dedup = Deduplicator()
    result = dedup.run(findings)
    assert len(result) == 2


def test_dedup_empty():
    dedup = Deduplicator()
    assert dedup.run([]) == []
