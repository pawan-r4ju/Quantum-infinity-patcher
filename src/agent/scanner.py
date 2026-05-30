"""Scanner — wraps Grype, Trivy, and language-native audit tools."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


class Finding:
    """Raw finding from a scanner."""

    def __init__(
        self,
        cve_id: str,
        severity: str,
        component: str,
        version: str,
        fixed_version: str = "",
        ecosystem: str = "",
        scanner: str = "",
        title: str = "",
        description: str = "",
        cvss_score: float = 0.0,
        file_path: str = "",
    ):
        self.cve_id = cve_id
        self.severity = severity.lower()
        self.component = component
        self.version = version
        self.fixed_version = fixed_version
        self.ecosystem = ecosystem
        self.scanner = scanner
        self.title = title
        self.description = description
        self.cvss_score = cvss_score
        self.file_path = file_path

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "severity": self.severity,
            "component": self.component,
            "version": self.version,
            "fixed_version": self.fixed_version,
            "ecosystem": self.ecosystem,
            "scanner": self.scanner,
            "title": self.title,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "file_path": self.file_path,
        }


class Scanner:
    """Runs vulnerability scanners against the repo."""

    def __init__(self, repo_path: Path, scanners: list[str], skip_paths: list[str]):
        self.repo_path = repo_path
        self.scanners = scanners
        self.skip_paths = skip_paths

    def run(self) -> list[Finding]:
        """Run all configured scanners and collect findings."""
        all_findings: list[Finding] = []

        for scanner_name in self.scanners:
            scanner_name = scanner_name.strip()
            if scanner_name == "grype":
                all_findings.extend(self._run_grype())
            elif scanner_name == "trivy":
                all_findings.extend(self._run_trivy())
            elif scanner_name == "native":
                all_findings.extend(self._run_native())
            else:
                print(f"  ⚠️  Unknown scanner: {scanner_name}")

        return all_findings

    def _run_grype(self) -> list[Finding]:
        """Run Anchore Grype scanner."""
        print("  Running Grype...")
        try:
            result = subprocess.run(
                ["grype", str(self.repo_path), "-o", "json", "--quiet"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode not in (0, 1):  # 1 = vulnerabilities found
                print(f"  ⚠️  Grype error: {result.stderr[:200]}")
                return []

            data = json.loads(result.stdout)
            return self._parse_grype_output(data)
        except FileNotFoundError:
            print("  ⚠️  Grype not installed")
            return []
        except subprocess.TimeoutExpired:
            print("  ⚠️  Grype timed out")
            return []
        except json.JSONDecodeError:
            print("  ⚠️  Grype output parse error")
            return []

    def _parse_grype_output(self, data: dict) -> list[Finding]:
        """Parse Grype JSON output into Findings."""
        findings = []
        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            cve_id = vuln.get("id", "")
            severity = vuln.get("severity", "unknown").lower()
            component = artifact.get("name", "")
            version = artifact.get("version", "")
            ecosystem = artifact.get("type", "")

            # Get fixed version
            fixed_version = ""
            fix_info = vuln.get("fix", {})
            if fix_info.get("state") == "fixed":
                versions = fix_info.get("versions", [])
                if versions:
                    fixed_version = versions[0]

            # CVSS score
            cvss_score = 0.0
            cvss_list = vuln.get("cvss", [])
            if cvss_list:
                cvss_score = cvss_list[0].get("metrics", {}).get("baseScore", 0.0)

            findings.append(Finding(
                cve_id=cve_id,
                severity=severity,
                component=component,
                version=version,
                fixed_version=fixed_version,
                ecosystem=ecosystem,
                scanner="grype",
                title=vuln.get("description", "")[:100],
                description=vuln.get("description", ""),
                cvss_score=cvss_score,
            ))

        print(f"    → {len(findings)} findings from Grype")
        return findings

    def _run_trivy(self) -> list[Finding]:
        """Run Aqua Trivy scanner."""
        print("  Running Trivy...")
        try:
            result = subprocess.run(
                [
                    "trivy", "fs", str(self.repo_path),
                    "--format", "json",
                    "--quiet",
                    "--scanners", "vuln",
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode not in (0, 1):
                print(f"  ⚠️  Trivy error: {result.stderr[:200]}")
                return []

            data = json.loads(result.stdout)
            return self._parse_trivy_output(data)
        except FileNotFoundError:
            print("  ⚠️  Trivy not installed")
            return []
        except subprocess.TimeoutExpired:
            print("  ⚠️  Trivy timed out")
            return []
        except json.JSONDecodeError:
            print("  ⚠️  Trivy output parse error")
            return []

    def _parse_trivy_output(self, data: dict) -> list[Finding]:
        """Parse Trivy JSON output into Findings."""
        findings = []
        results = data.get("Results", [])

        for result in results:
            target = result.get("Target", "")
            vulns = result.get("Vulnerabilities", []) or []

            for vuln in vulns:
                findings.append(Finding(
                    cve_id=vuln.get("VulnerabilityID", ""),
                    severity=vuln.get("Severity", "unknown").lower(),
                    component=vuln.get("PkgName", ""),
                    version=vuln.get("InstalledVersion", ""),
                    fixed_version=vuln.get("FixedVersion", ""),
                    ecosystem=result.get("Type", ""),
                    scanner="trivy",
                    title=vuln.get("Title", ""),
                    description=vuln.get("Description", ""),
                    cvss_score=vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", 0.0),
                    file_path=target,
                ))

        print(f"    → {len(findings)} findings from Trivy")
        return findings

    def _run_native(self) -> list[Finding]:
        """Run language-native audit tools based on detected ecosystem."""
        findings: list[Finding] = []

        # Detect Python
        if (self.repo_path / "requirements.txt").exists() or (self.repo_path / "pyproject.toml").exists():
            findings.extend(self._run_pip_audit())

        # Detect Node.js
        if (self.repo_path / "package.json").exists():
            findings.extend(self._run_npm_audit())

        # Detect Go
        if (self.repo_path / "go.mod").exists():
            findings.extend(self._run_govulncheck())

        return findings

    def _run_pip_audit(self) -> list[Finding]:
        """Run pip-audit for Python projects."""
        print("  Running pip-audit...")
        req_file = self.repo_path / "requirements.txt"
        if not req_file.exists():
            return []

        try:
            result = subprocess.run(
                ["pip-audit", "-r", str(req_file), "-f", "json", "--progress-spinner=off"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            data = json.loads(result.stdout) if result.stdout else []
            findings = []
            for vuln in data:
                for v in vuln.get("vulns", []):
                    findings.append(Finding(
                        cve_id=v.get("id", ""),
                        severity="high",  # pip-audit doesn't always give severity
                        component=vuln.get("name", ""),
                        version=vuln.get("version", ""),
                        fixed_version=v.get("fix_versions", [""])[0] if v.get("fix_versions") else "",
                        ecosystem="python",
                        scanner="pip-audit",
                        description=v.get("description", ""),
                    ))
            print(f"    → {len(findings)} findings from pip-audit")
            return findings
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            print("  ⚠️  pip-audit failed or not available")
            return []

    def _run_npm_audit(self) -> list[Finding]:
        """Run npm audit for Node.js projects."""
        print("  Running npm audit...")
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(self.repo_path),
            )
            data = json.loads(result.stdout) if result.stdout else {}
            findings = []

            vulnerabilities = data.get("vulnerabilities", {})
            for name, info in vulnerabilities.items():
                findings.append(Finding(
                    cve_id=info.get("via", [{}])[0].get("url", "") if isinstance(info.get("via", [{}])[0], dict) else "",
                    severity=info.get("severity", "unknown"),
                    component=name,
                    version=info.get("range", ""),
                    fixed_version=info.get("fixAvailable", {}).get("version", "") if isinstance(info.get("fixAvailable"), dict) else "",
                    ecosystem="npm",
                    scanner="npm-audit",
                ))
            print(f"    → {len(findings)} findings from npm audit")
            return findings
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            print("  ⚠️  npm audit failed or not available")
            return []

    def _run_govulncheck(self) -> list[Finding]:
        """Run govulncheck for Go projects."""
        print("  Running govulncheck...")
        try:
            result = subprocess.run(
                ["govulncheck", "-json", "./..."],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(self.repo_path),
            )
            # govulncheck JSON output is NDJSON
            findings = []
            for line in result.stdout.splitlines():
                try:
                    entry = json.loads(line)
                    if "finding" in entry:
                        f = entry["finding"]
                        findings.append(Finding(
                            cve_id=f.get("osv", ""),
                            severity="high",
                            component=f.get("trace", [{}])[0].get("module", ""),
                            version=f.get("trace", [{}])[0].get("version", ""),
                            fixed_version=f.get("fixed_version", ""),
                            ecosystem="go",
                            scanner="govulncheck",
                        ))
                except json.JSONDecodeError:
                    continue
            print(f"    → {len(findings)} findings from govulncheck")
            return findings
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print("  ⚠️  govulncheck failed or not available")
            return []
