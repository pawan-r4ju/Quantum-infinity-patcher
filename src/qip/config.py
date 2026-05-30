"""Configuration loader — resolves flags → env → repo → user → defaults."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml

from qip.models import QipConfig

# Config resolution order (highest priority first):
# 1. CLI flags (passed directly)
# 2. Environment variables (QIP_<SECTION>_<KEY>)
# 3. Repo-level config (<repo>/.qip/config.yaml)
# 4. User-level config (~/.qip/config.yaml)
# 5. Defaults (Pydantic model defaults)

USER_CONFIG_DIR = Path.home() / ".qip"
USER_CONFIG_FILE = USER_CONFIG_DIR / "config.yaml"
REPO_CONFIG_DIR = ".qip"
REPO_CONFIG_FILE = "config.yaml"


def get_user_config_path() -> Path:
    """Get the user-level config file path."""
    return USER_CONFIG_FILE


def get_repo_config_path(repo_path: Optional[Path] = None) -> Optional[Path]:
    """Get the repo-level config file path."""
    if repo_path is None:
        repo_path = Path.cwd()
    config_path = repo_path / REPO_CONFIG_DIR / REPO_CONFIG_FILE
    if config_path.exists():
        return config_path
    return None


def _load_yaml_file(path: Path) -> dict:
    """Load a YAML file, returning empty dict if not found."""
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep merge override into base (override wins)."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _env_overrides() -> dict:
    """Collect QIP_* environment variables and structure them."""
    overrides: dict[str, Any] = {}
    prefix = "QIP_"
    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue
        parts = key[len(prefix):].lower().split("_", 1)
        if len(parts) == 2:
            section, field = parts
            if section not in overrides:
                overrides[section] = {}
            # Try to parse as int/bool
            overrides[section][field] = _parse_env_value(value)
        elif len(parts) == 1:
            overrides[parts[0]] = _parse_env_value(value)
    return overrides


def _parse_env_value(value: str) -> Any:
    """Parse environment variable value to appropriate Python type."""
    if value.lower() in ("true", "1", "yes"):
        return True
    if value.lower() in ("false", "0", "no"):
        return False
    try:
        return int(value)
    except ValueError:
        pass
    return value


def load_config(
    repo_path: Optional[Path] = None,
    overrides: Optional[dict] = None,
) -> QipConfig:
    """
    Load and resolve QIP configuration.

    Resolution: defaults → user config → repo config → env vars → explicit overrides
    """
    # Start with empty (Pydantic defaults will fill in)
    merged: dict = {}

    # Layer 1: User config
    user_config = _load_yaml_file(get_user_config_path())
    merged = _deep_merge(merged, user_config)

    # Layer 2: Repo config
    repo_config_path = get_repo_config_path(repo_path)
    if repo_config_path:
        repo_config = _load_yaml_file(repo_config_path)
        merged = _deep_merge(merged, repo_config)

    # Layer 3: Environment variables
    env_config = _env_overrides()
    merged = _deep_merge(merged, env_config)

    # Layer 4: Explicit overrides (CLI flags)
    if overrides:
        merged = _deep_merge(merged, overrides)

    # Parse through Pydantic for validation + defaults
    return QipConfig(**merged)


def init_repo_config(repo_path: Path) -> Path:
    """Initialize .qip/config.yaml in a repository."""
    qip_dir = repo_path / REPO_CONFIG_DIR
    qip_dir.mkdir(parents=True, exist_ok=True)

    config_path = qip_dir / REPO_CONFIG_FILE
    if not config_path.exists():
        default_config = """\
# QIP Repository Configuration
# See: https://github.com/your-org/quantum-infinity-patcher/blob/main/PRD.md#configuration

scan:
  scanners: [grype, trivy, native]
  severity_threshold: medium
  skip_paths:
    - "test/"
    - "tests/"
    - "docs/"
    - "node_modules/"

validate:
  test_command: ""  # auto-detect or set: "pytest", "npm test", etc.

deploy:
  branch_prefix: "fix/qip-"
  auto_push: false
"""
        config_path.write_text(default_config, encoding="utf-8")

    # Create .gitignore in .qip/
    gitignore_path = qip_dir / ".gitignore"
    if not gitignore_path.exists():
        gitignore_path.write_text(
            "scans/\napproved/\nhistory.db\n", encoding="utf-8"
        )

    return config_path


def ensure_user_dirs() -> None:
    """Ensure ~/.qip/ directory structure exists."""
    dirs = [
        USER_CONFIG_DIR,
        USER_CONFIG_DIR / "vuln-db",
        USER_CONFIG_DIR / "skills",
        USER_CONFIG_DIR / "cache",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
