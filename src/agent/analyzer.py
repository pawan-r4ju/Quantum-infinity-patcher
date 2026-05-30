"""Analyzer — reachability analysis, priority scoring, enrichment."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from agent.scanner import Finding


class Analyzer:
    """Analyze findings for reachability and priority."""

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path

    def run(self, findings: list[Finding]) -> list[Finding]:
        """Analyze findings: reachability, direct vs transitive, priority."""
        for finding in findings:
            # Check if dependency is direct
            finding.direct_dep = self._is_direct_dependency(finding)

            # Basic reachability (check if component is imported in source)
            finding.reachable = self._check_reachability(finding)

            # Adjust priority based on analysis
            finding.priority_score = self._calculate_priority(finding)

        # Sort by priority (highest first)
        findings.sort(key=lambda f: -getattr(f, "priority_score", 0))

        return findings

    def _is_direct_dependency(self, finding: Finding) -> bool:
        """Check if component is a direct dependency."""
        component = finding.component

        # Check Python requirements.txt
        req_file = self.repo_path / "requirements.txt"
        if req_file.exists() and finding.ecosystem == "python":
            content = req_file.read_text(encoding="utf-8").lower()
            return component.lower() in content

        # Check Node package.json
        pkg_file = self.repo_path / "package.json"
        if pkg_file.exists() and finding.ecosystem in ("npm", "node"):
            try:
                pkg = json.loads(pkg_file.read_text(encoding="utf-8"))
                deps = pkg.get("dependencies", {})
                dev_deps = pkg.get("devDependencies", {})
                return component in deps or component in dev_deps
            except json.JSONDecodeError:
                pass

        # Check Go go.mod
        gomod = self.repo_path / "go.mod"
        if gomod.exists() and finding.ecosystem == "go":
            content = gomod.read_text(encoding="utf-8")
            return component in content

        return True  # Assume direct if we can't tell

    def _check_reachability(self, finding: Finding) -> bool:
        """Basic reachability: is the component imported/used in source?"""
        component = finding.component
        if not component:
            return True  # Assume reachable if we can't check

        # Search for import statements in source files
        search_patterns = [
            f"import {component}",
            f"from {component}",
            f"require('{component}'",
            f'require("{component}"',
            f'import "{component}"',
            f"import '{component}'",
        ]

        # Search Python/JS/Go source files
        extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".go"}
        for src_file in self.repo_path.rglob("*"):
            if src_file.suffix not in extensions:
                continue
            if any(skip in str(src_file) for skip in ["node_modules", "vendor", ".git", "test"]):
                continue
            try:
                content = src_file.read_text(encoding="utf-8", errors="ignore")
                for pattern in search_patterns:
                    if pattern in content:
                        return True
            except (OSError, UnicodeDecodeError):
                continue

        return False

    def _calculate_priority(self, finding: Finding) -> float:
        """Calculate priority score (0-100) for a finding."""
        score = 0.0

        # Severity weight (0-40)
        severity_scores = {"critical": 40, "high": 30, "medium": 20, "low": 10}
        score += severity_scores.get(finding.severity, 5)

        # CVSS score (0-20)
        score += (finding.cvss_score / 10.0) * 20

        # Fix available (0-20)
        if finding.fixed_version:
            score += 20

        # Reachability (0-10)
        if getattr(finding, "reachable", True):
            score += 10

        # Direct dependency (0-10)
        if getattr(finding, "direct_dep", True):
            score += 10

        return score
