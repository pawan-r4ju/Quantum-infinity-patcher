"""System health checks — `qip doctor`."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

from qip.config import USER_CONFIG_DIR, get_user_config_path
from qip.docker_manager import DockerManager
from qip.models import QipConfig

console = Console()


class DoctorCheck:
    """Result of a single doctor check."""

    def __init__(self, name: str, ok: bool, detail: str, warning: str = ""):
        self.name = name
        self.ok = ok
        self.detail = detail
        self.warning = warning


def check_python() -> DoctorCheck:
    """Check Python version."""
    import sys
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    ok = sys.version_info >= (3, 11)
    return DoctorCheck("Python", ok, version)


def check_docker() -> DoctorCheck:
    """Check Docker availability."""
    try:
        result = subprocess.run(
            ["docker", "--version"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            # Check if daemon is running
            ping = subprocess.run(
                ["docker", "info"], capture_output=True, text=True, timeout=10
            )
            if ping.returncode == 0:
                return DoctorCheck("Docker", True, version)
            return DoctorCheck("Docker", False, "Installed but daemon not running")
        return DoctorCheck("Docker", False, "Command failed")
    except FileNotFoundError:
        return DoctorCheck("Docker", False, "Not installed")
    except subprocess.TimeoutExpired:
        return DoctorCheck("Docker", False, "Timeout checking Docker")


def check_git() -> DoctorCheck:
    """Check Git availability."""
    try:
        result = subprocess.run(
            ["git", "--version"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return DoctorCheck("Git", True, result.stdout.strip())
        return DoctorCheck("Git", False, "Command failed")
    except FileNotFoundError:
        return DoctorCheck("Git", False, "Not installed")


def check_disk() -> DoctorCheck:
    """Check available disk space."""
    import shutil as sh
    home = Path.home()
    usage = sh.disk_usage(home)
    free_gb = usage.free / (1024**3)
    ok = free_gb >= 5.0
    detail = f"{free_gb:.1f} GB free"
    warning = "" if ok else "Recommend at least 5 GB free"
    return DoctorCheck("Disk", ok, detail, warning)


def check_agent_image(config: QipConfig) -> DoctorCheck:
    """Check if agent Docker image exists."""
    dm = DockerManager(config)
    if not dm.is_docker_running():
        return DoctorCheck("Agent Image", False, "Docker not running")
    info = dm.get_image_info()
    if info:
        return DoctorCheck("Agent Image", True, f"{config.agent.image} ({info['id']})")
    return DoctorCheck(
        "Agent Image", False, f"{config.agent.image} not found (run `qip agent build`)"
    )


def check_vuln_db() -> DoctorCheck:
    """Check vulnerability database status."""
    db_path = USER_CONFIG_DIR / "vuln-db"
    if not db_path.exists() or not any(db_path.iterdir()):
        return DoctorCheck("Vuln DB", False, "Not synced (run `qip db update`)")
    # Count files as proxy for DB content
    files = list(db_path.rglob("*"))
    return DoctorCheck("Vuln DB", True, f"Synced ({len(files)} files)")


def check_config() -> DoctorCheck:
    """Check config validity."""
    config_path = get_user_config_path()
    if not config_path.exists():
        return DoctorCheck("Config", True, "Using defaults (no user config)")
    try:
        from qip.config import load_config
        load_config()
        return DoctorCheck("Config", True, f"Valid ({config_path})")
    except Exception as e:
        return DoctorCheck("Config", False, f"Invalid: {e}")


def run_doctor(config: QipConfig) -> list[DoctorCheck]:
    """Run all doctor checks."""
    checks = [
        check_python(),
        check_docker(),
        check_git(),
        check_disk(),
        check_agent_image(config),
        check_vuln_db(),
        check_config(),
    ]
    return checks


def print_doctor_results(checks: list[DoctorCheck]) -> bool:
    """Print doctor results. Returns True if all passed."""
    all_ok = True
    for check in checks:
        if check.ok:
            icon = "✅"
            style = "green"
        else:
            icon = "❌"
            style = "red"
            all_ok = False

        line = f"{icon} {check.name:<14} {check.detail}"
        console.print(f"[{style}]{line}[/{style}]")

        if check.warning:
            console.print(f"   [yellow]⚠️  {check.warning}[/yellow]")

    return all_ok
