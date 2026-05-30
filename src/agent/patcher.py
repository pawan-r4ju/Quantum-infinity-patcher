"""Patcher — generates fix patches for vulnerabilities."""

from __future__ import annotations

import hashlib
from pathlib import Path

from agent.scanner import Finding
from agent.patchers.dep_bump import DepBumpPatcher


class PatchResult:
    """A generated patch."""

    def __init__(
        self,
        patch_id: str,
        cve_id: str,
        component: str,
        old_version: str,
        new_version: str,
        fix_type: str,
        confidence: str,
        diff_content: str,
        patch_file: str,
        description: str = "",
    ):
        self.patch_id = patch_id
        self.cve_id = cve_id
        self.component = component
        self.old_version = old_version
        self.new_version = new_version
        self.fix_type = fix_type
        self.confidence = confidence
        self.diff_content = diff_content
        self.patch_file = patch_file
        self.description = description
        self.test_result = "skip"

    def to_dict(self) -> dict:
        return {
            "patch_id": self.patch_id,
            "cve_id": self.cve_id,
            "component": self.component,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "fix_type": self.fix_type,
            "confidence": self.confidence,
            "patch_file": self.patch_file,
            "description": self.description,
            "test_result": self.test_result,
        }


class Patcher:
    """Generates patches for fixable vulnerabilities."""

    def __init__(self, repo_path: Path, output_path: Path):
        self.repo_path = repo_path
        self.output_path = output_path
        self.patches_dir = output_path / "patches"
        self.patches_dir.mkdir(parents=True, exist_ok=True)

        # Initialize patchers
        self.dep_bump = DepBumpPatcher(repo_path)

    def run(self, findings: list[Finding]) -> list[PatchResult]:
        """Generate patches for all fixable findings."""
        patches: list[PatchResult] = []
        patch_counter = 0

        for finding in findings:
            # Skip if no fix available
            if not finding.fixed_version:
                continue

            patch_counter += 1
            patch_id = self._generate_patch_id(finding, patch_counter)

            # Try dependency bump (most common, highest confidence)
            result = self.dep_bump.patch(finding)
            if result:
                diff_content, description = result
                patch_file = f"{patch_counter:03d}-{finding.cve_id}.patch"

                # Write patch file
                patch_path = self.patches_dir / patch_file
                patch_path.write_text(diff_content, encoding="utf-8")

                # Write metadata
                patch_result = PatchResult(
                    patch_id=patch_id,
                    cve_id=finding.cve_id,
                    component=finding.component,
                    old_version=finding.version,
                    new_version=finding.fixed_version,
                    fix_type="dep-bump",
                    confidence="high",
                    diff_content=diff_content,
                    patch_file=patch_file,
                    description=description,
                )
                patches.append(patch_result)

                # Write metadata JSON alongside patch
                import json
                meta_path = patch_path.with_suffix(".json")
                meta_path.write_text(
                    json.dumps(patch_result.to_dict(), indent=2),
                    encoding="utf-8",
                )

                print(f"    ✓ {finding.cve_id}: {finding.component} "
                      f"{finding.version} → {finding.fixed_version}")
            else:
                print(f"    ⚠ {finding.cve_id}: no auto-fix for {finding.component}")

        return patches

    def _generate_patch_id(self, finding: Finding, counter: int) -> str:
        """Generate a unique patch ID."""
        hash_input = f"{finding.cve_id}{finding.component}{counter}"
        short_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:8]
        return f"patch_{short_hash}"
