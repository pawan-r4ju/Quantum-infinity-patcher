"""Docker container lifecycle management for QIP agent."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

import docker
from docker.errors import BuildError, ContainerError, ImageNotFound
from rich.console import Console

from qip.models import AgentConfig, QipConfig
from qip.utils import generate_run_id

console = Console()


class DockerManager:
    """Manages the QIP agent Docker container lifecycle."""

    def __init__(self, config: QipConfig):
        self.config = config
        self.agent_config = config.agent
        self._client: Optional[docker.DockerClient] = None

    @property
    def client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def is_docker_running(self) -> bool:
        """Check if Docker daemon is accessible."""
        try:
            self.client.ping()
            return True
        except Exception:
            return False

    def image_exists(self) -> bool:
        """Check if the QIP agent image exists locally."""
        try:
            self.client.images.get(self.agent_config.image)
            return True
        except ImageNotFound:
            return False

    def build_image(self, context_path: Path) -> bool:
        """Build the QIP agent Docker image."""
        console.print("[yellow]🐳 Building QIP agent image...[/yellow]")
        try:
            image, logs = self.client.images.build(
                path=str(context_path),
                tag=self.agent_config.image,
                rm=True,
                forcerm=True,
            )
            for log in logs:
                if "stream" in log:
                    line = log["stream"].strip()
                    if line:
                        console.print(f"  [dim]{line}[/dim]")
            console.print(f"[green]✅ Image built: {self.agent_config.image}[/green]")
            return True
        except BuildError as e:
            console.print(f"[red]❌ Build failed: {e}[/red]")
            return False

    def run_scan(
        self,
        repo_path: Path,
        output_path: Path,
        run_id: str,
    ) -> tuple[bool, str]:
        """
        Run the QIP agent container for a scan.

        Returns (success, container_logs).
        """
        repo_path = repo_path.resolve()
        output_path = output_path.resolve()
        output_path.mkdir(parents=True, exist_ok=True)

        vuln_db_path = Path.home() / ".qip" / "vuln-db"
        vuln_db_path.mkdir(parents=True, exist_ok=True)

        # Volume mounts
        volumes = {
            str(repo_path): {"bind": "/repo", "mode": "ro"},
            str(output_path): {"bind": "/output", "mode": "rw"},
            str(vuln_db_path): {"bind": "/vuln-db", "mode": "ro"},
        }

        # Environment variables for agent
        environment = {
            "QIP_RUN_ID": run_id,
            "QIP_SEVERITY_THRESHOLD": self.config.scan.severity_threshold.value,
            "QIP_SCANNERS": ",".join(self.config.scan.scanners),
            "QIP_SKIP_PATHS": ",".join(self.config.scan.skip_paths),
            "QIP_TEST_COMMAND": self.config.validate.test_command,
            "QIP_VALIDATE_ENABLED": str(self.config.validate.enabled).lower(),
        }

        # Parse memory limit
        mem_limit = self.agent_config.memory

        console.print(f"[cyan]🚀 Starting agent container (run: {run_id})...[/cyan]")
        console.print(f"   Repo:   {repo_path}")
        console.print(f"   Output: {output_path}")
        console.print(f"   Limits: {self.agent_config.cpus} CPU, {mem_limit} RAM")

        try:
            container = self.client.containers.run(
                image=self.agent_config.image,
                volumes=volumes,
                environment=environment,
                network_mode="none",  # No network during scan
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                pids_limit=self.agent_config.pids_limit,
                mem_limit=mem_limit,
                nano_cpus=int(self.agent_config.cpus * 1e9),
                user="1000:1000",
                remove=True,
                detach=False,
                stdout=True,
                stderr=True,
            )

            logs = container.decode("utf-8") if isinstance(container, bytes) else str(container)
            console.print("[green]✅ Agent completed successfully[/green]")
            return True, logs

        except ContainerError as e:
            logs = e.stderr.decode("utf-8") if e.stderr else str(e)
            console.print(f"[red]❌ Agent failed (exit code {e.exit_status})[/red]")
            return False, logs
        except Exception as e:
            console.print(f"[red]❌ Container error: {e}[/red]")
            return False, str(e)

    def get_image_info(self) -> Optional[dict]:
        """Get info about the agent image."""
        try:
            image = self.client.images.get(self.agent_config.image)
            return {
                "id": image.short_id,
                "tags": image.tags,
                "created": image.attrs.get("Created", ""),
                "size": image.attrs.get("Size", 0),
            }
        except ImageNotFound:
            return None

    def cleanup_old_containers(self) -> int:
        """Remove any orphaned QIP agent containers."""
        removed = 0
        containers = self.client.containers.list(
            all=True, filters={"ancestor": self.agent_config.image}
        )
        for container in containers:
            if container.status in ("exited", "dead"):
                container.remove(force=True)
                removed += 1
        return removed
