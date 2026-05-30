"""Validator — runs tests against patched code to verify fixes."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from agent.patcher import PatchResult


class Validator:
    """Validates patches by running the repo's test suite."""

    def __init__(self, repo_path: Path, test_command: str, output_path: Path):
        self.repo_path = repo_path
        self.test_command = test_command
        self.output_path = output_path
        self.evidence_dir = output_path / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def run(self, patches: list[PatchResult]) -> list[PatchResult]:
        """Validate each patch by applying and running tests."""
        if not self.test_command:
            print("  No test command configured, skipping validation")
            return patches

        for patch in patches:
            result = self._validate_single(patch)
            patch.test_result = result
            status_icon = {"pass": "✅", "fail": "❌", "skip": "⚠️"}.get(result, "?")
            print(f"    {status_icon} {patch.cve_id}: test {result}")

        return patches

    def _validate_single(self, patch: PatchResult) -> str:
        """Validate a single patch. Returns 'pass', 'fail', or 'skip'."""
        # Create a temporary working copy
        with tempfile.TemporaryDirectory(prefix="qip_validate_") as tmp_dir:
            work_dir = Path(tmp_dir) / "repo"

            try:
                # Copy repo to temp (since /repo is read-only)
                shutil.copytree(self.repo_path, work_dir, dirs_exist_ok=True)
            except (OSError, shutil.Error) as e:
                print(f"    ⚠️  Could not copy repo for validation: {e}")
                return "skip"

            # Apply the patch
            patch_file = self.output_path / "patches" / patch.patch_file
            if not patch_file.exists():
                return "skip"

            try:
                subprocess.run(
                    ["git", "apply", str(patch_file)],
                    cwd=str(work_dir),
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=True,
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                return "fail"

            # Run tests
            try:
                result = subprocess.run(
                    self.test_command.split(),
                    cwd=str(work_dir),
                    capture_output=True,
                    text=True,
                    timeout=300,
                )

                # Save evidence
                evidence_file = self.evidence_dir / f"{patch.patch_id}_test.log"
                evidence_file.write_text(
                    f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}\n"
                    f"\nExit code: {result.returncode}",
                    encoding="utf-8",
                )

                return "pass" if result.returncode == 0 else "fail"
            except subprocess.TimeoutExpired:
                return "fail"
            except FileNotFoundError:
                return "skip"
