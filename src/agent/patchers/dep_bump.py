"""Dependency bump patcher — upgrades vulnerable dependencies to safe versions."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from agent.scanner import Finding


class DepBumpPatcher:
    """Generates dependency bump patches for vulnerable packages."""

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path

    def patch(self, finding: Finding) -> Optional[tuple[str, str]]:
        """
        Generate a dependency bump patch.

        Returns (diff_content, description) or None if not patchable.
        """
        if not finding.fixed_version:
            return None

        ecosystem = finding.ecosystem.lower()

        if ecosystem in ("python", "pip"):
            return self._patch_python(finding)
        elif ecosystem in ("npm", "node"):
            return self._patch_npm(finding)
        elif ecosystem == "go":
            return self._patch_go(finding)
        elif ecosystem in ("cargo", "rust"):
            return self._patch_cargo(finding)

        return None

    def _patch_python(self, finding: Finding) -> Optional[tuple[str, str]]:
        """Patch Python requirements.txt or pyproject.toml."""
        # Try requirements.txt first
        req_file = self.repo_path / "requirements.txt"
        if req_file.exists():
            return self._patch_requirements_txt(req_file, finding)

        # Try pyproject.toml
        pyproject = self.repo_path / "pyproject.toml"
        if pyproject.exists():
            return self._patch_pyproject_toml(pyproject, finding)

        return None

    def _patch_requirements_txt(self, req_file: Path, finding: Finding) -> Optional[tuple[str, str]]:
        """Patch a requirements.txt file."""
        content = req_file.read_text(encoding="utf-8")
        lines = content.splitlines(keepends=True)
        new_lines = []
        patched = False

        for line in lines:
            # Match: package==version, package>=version, package~=version
            pattern = rf'^({re.escape(finding.component)})\s*([=~><!]+)\s*{re.escape(finding.version)}'
            match = re.match(pattern, line.strip(), re.IGNORECASE)
            if match:
                pkg_name = match.group(1)
                operator = match.group(2)
                # Use >= for the fixed version
                new_line = f"{pkg_name}>={finding.fixed_version}\n"
                new_lines.append(new_line)
                patched = True
            else:
                new_lines.append(line)

        if not patched:
            return None

        # Generate unified diff
        diff = self._generate_diff(
            f"a/{req_file.name}",
            f"b/{req_file.name}",
            content,
            "".join(new_lines),
        )

        description = (
            f"Bump {finding.component} from {finding.version} to >={finding.fixed_version} "
            f"to fix {finding.cve_id}"
        )
        return diff, description

    def _patch_pyproject_toml(self, pyproject: Path, finding: Finding) -> Optional[tuple[str, str]]:
        """Patch a pyproject.toml file."""
        content = pyproject.read_text(encoding="utf-8")

        # Simple regex replacement for dependency version
        pattern = rf'("{re.escape(finding.component)}"?\s*[><=~!]*\s*){re.escape(finding.version)}'
        replacement = rf'\g<1>{finding.fixed_version}'

        new_content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
        if new_content == content:
            # Try alternative patterns
            pattern2 = rf'({re.escape(finding.component)}\s*=\s*"[><=~!]*){re.escape(finding.version)}'
            new_content = re.sub(pattern2, rf'\g<1>{finding.fixed_version}', content)

        if new_content == content:
            return None

        diff = self._generate_diff("a/pyproject.toml", "b/pyproject.toml", content, new_content)
        description = f"Bump {finding.component} to {finding.fixed_version} in pyproject.toml"
        return diff, description

    def _patch_npm(self, finding: Finding) -> Optional[tuple[str, str]]:
        """Patch package.json for Node.js projects."""
        pkg_file = self.repo_path / "package.json"
        if not pkg_file.exists():
            return None

        content = pkg_file.read_text(encoding="utf-8")
        try:
            pkg = json.loads(content)
        except json.JSONDecodeError:
            return None

        patched = False
        for dep_key in ("dependencies", "devDependencies"):
            deps = pkg.get(dep_key, {})
            if finding.component in deps:
                # Update version (preserve prefix like ^ or ~)
                old_ver = deps[finding.component]
                prefix = ""
                for p in ("^", "~", ">=", ">", "<=", "<"):
                    if old_ver.startswith(p):
                        prefix = p
                        break
                deps[finding.component] = f"{prefix}{finding.fixed_version}"
                patched = True
                break

        if not patched:
            return None

        new_content = json.dumps(pkg, indent=2, ensure_ascii=False) + "\n"
        diff = self._generate_diff("a/package.json", "b/package.json", content, new_content)
        description = f"Bump {finding.component} to {finding.fixed_version} in package.json"
        return diff, description

    def _patch_go(self, finding: Finding) -> Optional[tuple[str, str]]:
        """Patch go.mod for Go projects."""
        gomod = self.repo_path / "go.mod"
        if not gomod.exists():
            return None

        content = gomod.read_text(encoding="utf-8")
        # Replace version in go.mod
        pattern = rf'({re.escape(finding.component)}\s+)v{re.escape(finding.version)}'
        new_content = re.sub(pattern, rf'\g<1>v{finding.fixed_version}', content)

        if new_content == content:
            return None

        diff = self._generate_diff("a/go.mod", "b/go.mod", content, new_content)
        description = f"Bump {finding.component} to v{finding.fixed_version} in go.mod"
        return diff, description

    def _patch_cargo(self, finding: Finding) -> Optional[tuple[str, str]]:
        """Patch Cargo.toml for Rust projects."""
        cargo = self.repo_path / "Cargo.toml"
        if not cargo.exists():
            return None

        content = cargo.read_text(encoding="utf-8")
        pattern = rf'({re.escape(finding.component)}\s*=\s*"[~^>=<]*){re.escape(finding.version)}'
        new_content = re.sub(pattern, rf'\g<1>{finding.fixed_version}', content)

        if new_content == content:
            return None

        diff = self._generate_diff("a/Cargo.toml", "b/Cargo.toml", content, new_content)
        description = f"Bump {finding.component} to {finding.fixed_version} in Cargo.toml"
        return diff, description

    def _generate_diff(self, old_path: str, new_path: str, old_content: str, new_content: str) -> str:
        """Generate a unified diff in git format."""
        import difflib

        old_lines = old_content.splitlines(keepends=True)
        new_lines = new_content.splitlines(keepends=True)

        diff_lines = difflib.unified_diff(
            old_lines, new_lines,
            fromfile=old_path,
            tofile=new_path,
        )

        return "".join(diff_lines)
