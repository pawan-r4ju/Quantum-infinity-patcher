"""Shared utilities for QIP."""

from __future__ import annotations

import datetime
import hashlib
import platform
from pathlib import Path


def generate_run_id() -> str:
    """Generate a unique run ID: qip_YYYY-MM-DD_<short-hash>."""
    now = datetime.datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    hash_input = f"{now.isoformat()}{platform.node()}"
    short_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:6]
    return f"qip_{date_str}_{short_hash}"


def find_repo_root(path: Path | None = None) -> Path:
    """Walk up to find the git repo root (directory containing .git)."""
    if path is None:
        path = Path.cwd()
    path = path.resolve()

    current = path
    while current != current.parent:
        if (current / ".git").exists():
            return current
        current = current.parent

    # If no .git found, use the original path
    return path.resolve()


def human_duration(seconds: float) -> str:
    """Convert seconds to human-readable duration."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    if minutes < 60:
        return f"{minutes}m {secs:.0f}s"
    hours = minutes // 60
    mins = minutes % 60
    return f"{hours}h {mins}m"


def severity_emoji(severity: str) -> str:
    """Get emoji for severity level."""
    mapping = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "unknown": "⚪",
    }
    return mapping.get(severity.lower(), "⚪")
