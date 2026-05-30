"""Git operations — branch, apply patches, commit, push."""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Optional

from git import Repo
from git.exc import GitCommandError, InvalidGitRepositoryError
from rich.console import Console

from qip.models import DeployConfig, Patch

console = Console()


class Deployer:
    """Handles git operations for deploying approved patches."""

    def __init__(self, repo_path: Path, config: DeployConfig):
        self.repo_path = repo_path
        self.config = config
        self._repo: Optional[Repo] = None

    @property
    def repo(self) -> Repo:
        if self._repo is None:
            self._repo = Repo(self.repo_path)
        return self._repo

    def validate_repo(self) -> tuple[bool, str]:
        """Check repo is clean and ready for deployment."""
        try:
            repo = self.repo
        except InvalidGitRepositoryError:
            return False, f"Not a git repository: {self.repo_path}"

        if repo.is_dirty(untracked_files=True):
            return False, "Repository has uncommitted changes. Commit or stash first."

        return True, "OK"

    def create_branch(self, run_id: str) -> str:
        """Create a new branch for patches."""
        date_str = datetime.date.today().strftime("%Y%m%d")
        short_hash = run_id.split("_")[-1] if "_" in run_id else run_id[:6]
        branch_name = f"{self.config.branch_prefix}{date_str}-{short_hash}"

        current = self.repo.active_branch
        new_branch = self.repo.create_head(branch_name)
        new_branch.checkout()

        console.print(f"[green]Created branch: {branch_name}[/green]")
        return branch_name

    def apply_patch(self, patch_file: Path) -> bool:
        """Apply a single patch file using git apply."""
        try:
            self.repo.git.apply(str(patch_file), "--check")  # dry run first
            self.repo.git.apply(str(patch_file))
            return True
        except GitCommandError as e:
            console.print(f"[red]Failed to apply {patch_file.name}: {e}[/red]")
            return False

    def commit_patch(self, patch: Patch, run_id: str) -> bool:
        """Commit a single applied patch with structured message."""
        # Stage all changes
        self.repo.git.add(A=True)

        # Build commit message
        scope = patch.component.split("/")[-1] if "/" in patch.component else "deps"
        message = f"fix({scope}): patch {patch.cve_id} in {patch.component}\n\n"
        message += f"Component: {patch.component}"
        if patch.old_version and patch.new_version:
            message += f"@{patch.old_version} → {patch.new_version}"
        message += "\n"
        message += f"Type: {patch.fix_type.value}\n"
        message += f"Confidence: {patch.confidence.value}\n"
        message += f"\nPatched by: Quantum Infinity Patcher (run {run_id})\n"

        try:
            self.repo.git.commit(m=message)
            console.print(f"  [green]✓[/green] Committed: {patch.cve_id}")
            return True
        except GitCommandError as e:
            console.print(f"  [red]✗ Commit failed: {e}[/red]")
            return False

    def deploy_patches(
        self,
        patches: list[Patch],
        patch_dir: Path,
        run_id: str,
        dry_run: bool = False,
    ) -> tuple[int, int]:
        """
        Deploy all approved patches.

        Returns (applied_count, failed_count).
        """
        # Validate
        ok, msg = self.validate_repo()
        if not ok:
            console.print(f"[red]❌ {msg}[/red]")
            return 0, len(patches)

        if dry_run:
            console.print("[yellow]🔍 Dry run — no changes will be made[/yellow]")
            for p in patches:
                patch_file = patch_dir / p.patch_file
                try:
                    self.repo.git.apply(str(patch_file), "--check")
                    console.print(f"  [green]✓[/green] Would apply: {p.cve_id}")
                except GitCommandError:
                    console.print(f"  [red]✗[/red] Would fail: {p.cve_id}")
            return 0, 0

        # Create branch
        if self.config.create_branch:
            branch_name = self.create_branch(run_id)

        # Apply and commit each patch
        applied = 0
        failed = 0
        for patch in patches:
            patch_file = patch_dir / patch.patch_file
            if not patch_file.exists():
                console.print(f"  [red]✗ Patch file not found: {patch.patch_file}[/red]")
                failed += 1
                continue

            if self.apply_patch(patch_file):
                if self.config.commit_style == "one-per-patch":
                    self.commit_patch(patch, run_id)
                applied += 1
            else:
                failed += 1

        # Squash commit if configured
        if self.config.commit_style == "squash" and applied > 0:
            self.repo.git.add(A=True)
            message = f"fix: patch {applied} CVEs\n\nPatched by: Quantum Infinity Patcher (run {run_id})\n"
            self.repo.git.commit(m=message)

        # Push if configured
        if self.config.auto_push and applied > 0:
            try:
                self.repo.git.push("origin", branch_name)
                console.print(f"[green]Pushed to origin/{branch_name}[/green]")
            except GitCommandError as e:
                console.print(f"[yellow]Push failed (do it manually): {e}[/yellow]")

        return applied, failed
