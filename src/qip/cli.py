"""QIP CLI — main entry point for all commands."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from qip import __version__
from qip.config import ensure_user_dirs, init_repo_config, load_config
from qip.utils import find_repo_root, generate_run_id, human_duration, severity_emoji

console = Console()


@click.group()
@click.version_option(__version__, prog_name="qip")
def cli():
    """🛡️ Quantum Infinity Patcher — Local-first security CVE agent."""
    pass


# ─── qip init ─────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
def init(path: str):
    """Initialize QIP in a repository."""
    repo_path = Path(path).resolve()
    ensure_user_dirs()
    config_path = init_repo_config(repo_path)
    console.print(f"[green]✅ Initialized QIP in {repo_path}[/green]")
    console.print(f"   Config: {config_path}")
    console.print(f"   Edit .qip/config.yaml to customize scan settings")


# ─── qip scan ─────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low"]))
def scan(path: str, severity: Optional[str]):
    """Scan a repository for CVEs in a sandboxed Docker agent."""
    repo_path = find_repo_root(Path(path).resolve())
    overrides = {}
    if severity:
        overrides = {"scan": {"severity_threshold": severity}}

    config = load_config(repo_path, overrides)
    run_id = generate_run_id()

    # Ensure output directory
    scan_dir = repo_path / ".qip" / "scans" / run_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold cyan]🛡️  Quantum Infinity Patcher — Scan[/bold cyan]")
    console.print(f"   Run ID:    {run_id}")
    console.print(f"   Repo:      {repo_path}")
    console.print(f"   Threshold: {config.scan.severity_threshold.value}")
    console.print(f"   Scanners:  {', '.join(config.scan.scanners)}")
    console.print("")

    # Check Docker
    from qip.docker_manager import DockerManager
    dm = DockerManager(config)

    if not dm.is_docker_running():
        console.print("[red]❌ Docker is not running. Start Docker Desktop and try again.[/red]")
        sys.exit(1)

    # Build image if needed
    if not dm.image_exists():
        if config.agent.auto_build:
            project_root = Path(__file__).parent.parent.parent
            if not dm.build_image(project_root):
                sys.exit(1)
        else:
            console.print("[red]❌ Agent image not found. Run `qip agent build`.[/red]")
            sys.exit(1)

    # Record start in history
    from qip.history import HistoryDB
    from qip.models import RunStatus, ScanRun
    history = HistoryDB()
    run = ScanRun(run_id=run_id, repo_path=str(repo_path), config_snapshot=config.model_dump())
    history.record_run_start(run)

    # Run the scan
    start_time = time.time()
    success, logs = dm.run_scan(repo_path, scan_dir, run_id)
    duration = time.time() - start_time

    # Load results
    report_path = scan_dir / "report.json"
    if report_path.exists():
        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        findings_count = report.get("total_findings", 0)
        patches_count = report.get("total_patches", 0)
    else:
        findings_count = 0
        patches_count = 0

    # Print summary
    console.print("")
    console.print(f"[bold]{'─' * 50}[/bold]")
    console.print(f"[bold]Scan Complete[/bold] ({human_duration(duration)})")
    console.print(f"  Findings: {findings_count}")
    console.print(f"  Patches:  {patches_count}")

    if patches_count > 0:
        console.print("")
        console.print(f"[cyan]Run `qip review {run_id}` to review {patches_count} proposed fixes[/cyan]")

    # Update history
    status = RunStatus.COMPLETED if success else RunStatus.FAILED
    history.record_run_end(run_id, status, [], [], {"total": duration})
    history.close()


# ─── qip review ───────────────────────────────────────────────────────────────


@cli.command()
@click.argument("run_id", required=False)
@click.option("--port", default=None, type=int, help="Port for review server")
def review(run_id: Optional[str], port: Optional[int]):
    """Launch the local review UI for a scan run."""
    repo_path = find_repo_root()
    config = load_config(repo_path)

    # Find the scan directory
    scans_dir = repo_path / ".qip" / "scans"
    if not scans_dir.exists():
        console.print("[red]❌ No scans found. Run `qip scan` first.[/red]")
        sys.exit(1)

    if run_id:
        scan_dir = scans_dir / run_id
    else:
        # Use latest scan
        scan_dirs = sorted(scans_dir.iterdir(), reverse=True)
        if not scan_dirs:
            console.print("[red]❌ No scans found. Run `qip scan` first.[/red]")
            sys.exit(1)
        scan_dir = scan_dirs[0]
        run_id = scan_dir.name

    if not scan_dir.exists():
        console.print(f"[red]❌ Scan not found: {run_id}[/red]")
        sys.exit(1)

    from qip.reviewer import start_review_server
    review_port = port or config.review.port
    start_review_server(
        scan_dir=scan_dir,
        run_id=run_id,
        host=config.review.host,
        port=review_port,
        open_browser=config.review.auto_open_browser,
    )


# ─── qip deploy ───────────────────────────────────────────────────────────────


@cli.command()
@click.argument("run_id", required=False)
@click.option("--dry-run", is_flag=True, help="Preview without making changes")
def deploy(run_id: Optional[str], dry_run: bool):
    """Apply approved patches to the repository."""
    repo_path = find_repo_root()
    config = load_config(repo_path)

    # Find approved patches
    approved_dir = repo_path / ".qip" / "approved"
    if not approved_dir.exists() or not any(approved_dir.glob("*.patch")):
        console.print("[red]❌ No approved patches found. Run `qip review` first.[/red]")
        sys.exit(1)

    # Load patch metadata
    from qip.deployer import Deployer
    from qip.models import Confidence, FixType, Patch

    deployer = Deployer(repo_path, config.deploy)

    # Build patch objects from approved directory
    patches = []
    for patch_file in sorted(approved_dir.glob("*.patch")):
        meta_file = patch_file.with_suffix(".json")
        if meta_file.exists():
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            patches.append(Patch(
                patch_id=meta.get("patch_id", patch_file.stem),
                cve_id=meta.get("cve_id", "unknown"),
                component=meta.get("component", ""),
                old_version=meta.get("old_version", ""),
                new_version=meta.get("new_version", ""),
                fix_type=FixType(meta.get("fix_type", "dep-bump")),
                confidence=Confidence(meta.get("confidence", "medium")),
                patch_file=patch_file.name,
            ))
        else:
            patches.append(Patch(
                patch_id=patch_file.stem,
                cve_id=patch_file.stem,
                fix_type=FixType.DEP_BUMP,
                confidence=Confidence.MEDIUM,
                patch_file=patch_file.name,
            ))

    console.print(f"[bold cyan]🚀 Deploy — {len(patches)} approved patches[/bold cyan]")

    actual_run_id = run_id or generate_run_id()
    applied, failed = deployer.deploy_patches(patches, approved_dir, actual_run_id, dry_run)

    if not dry_run:
        console.print("")
        console.print(f"[green]✅ Applied: {applied}[/green]")
        if failed:
            console.print(f"[red]❌ Failed: {failed}[/red]")


# ─── qip doctor ───────────────────────────────────────────────────────────────


@cli.command()
def doctor():
    """Check system health and prerequisites."""
    from qip.doctor import print_doctor_results, run_doctor

    console.print("[bold cyan]🛡️  QIP Doctor[/bold cyan]")
    console.print("")

    config = load_config()
    checks = run_doctor(config)
    all_ok = print_doctor_results(checks)

    console.print("")
    if all_ok:
        console.print("[green]All checks passed! ✨[/green]")
    else:
        console.print("[yellow]Some issues found. Fix them and run again.[/yellow]")
        sys.exit(1)


# ─── qip status ───────────────────────────────────────────────────────────────


@cli.command()
def status():
    """Show current scan state and pending reviews."""
    repo_path = find_repo_root()

    scans_dir = repo_path / ".qip" / "scans"
    approved_dir = repo_path / ".qip" / "approved"

    pending_patches = len(list(approved_dir.glob("*.patch"))) if approved_dir.exists() else 0
    total_scans = len(list(scans_dir.iterdir())) if scans_dir.exists() else 0

    console.print(f"[bold cyan]🛡️  QIP Status[/bold cyan]")
    console.print(f"   Repo:     {repo_path}")
    console.print(f"   Scans:    {total_scans}")
    console.print(f"   Pending:  {pending_patches} approved patches ready to deploy")

    if pending_patches > 0:
        console.print(f"\n   [cyan]Run `qip deploy` to apply {pending_patches} patches[/cyan]")


# ─── qip history ──────────────────────────────────────────────────────────────


@cli.command()
@click.option("--limit", default=10, help="Number of runs to show")
def history(limit: int):
    """List past scan runs."""
    from qip.history import HistoryDB

    db = HistoryDB()
    runs = db.list_runs(limit=limit)
    db.close()

    if not runs:
        console.print("[dim]No scan history yet. Run `qip scan` to get started.[/dim]")
        return

    table = Table(title="Scan History")
    table.add_column("Run ID", style="cyan")
    table.add_column("Repo", style="dim")
    table.add_column("Findings")
    table.add_column("Patches")
    table.add_column("Status")
    table.add_column("Date")

    for run in runs:
        status_style = {
            "completed": "green",
            "failed": "red",
            "running": "yellow",
        }.get(run.status.value, "white")

        table.add_row(
            run.run_id,
            Path(run.repo_path).name,
            str(run.total_findings),
            str(run.total_patches),
            f"[{status_style}]{run.status.value}[/{status_style}]",
            run.date,
        )

    console.print(table)


# ─── qip db ──────────────────────────────────────────────────────────────────


@cli.group()
def db():
    """Manage the local vulnerability database."""
    pass


@db.command("update")
def db_update():
    """Sync the OSV vulnerability database to local cache."""
    from qip.config import USER_CONFIG_DIR

    db_path = USER_CONFIG_DIR / "vuln-db"
    db_path.mkdir(parents=True, exist_ok=True)

    console.print("[cyan]📦 Updating vulnerability database...[/cyan]")
    console.print(f"   Path: {db_path}")

    # Trigger Grype DB update
    import subprocess
    try:
        result = subprocess.run(
            ["grype", "db", "update"],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode == 0:
            console.print("[green]✅ Grype DB updated[/green]")
        else:
            console.print(f"[yellow]⚠️  Grype DB update: {result.stderr.strip()}[/yellow]")
    except FileNotFoundError:
        console.print("[dim]   Grype not found on host (will use container version)[/dim]")
    except subprocess.TimeoutExpired:
        console.print("[yellow]⚠️  Grype DB update timed out[/yellow]")

    console.print("[green]✅ Vulnerability database updated[/green]")


@db.command("status")
def db_status():
    """Show vulnerability database status."""
    from qip.config import USER_CONFIG_DIR

    db_path = USER_CONFIG_DIR / "vuln-db"
    if not db_path.exists():
        console.print("[red]❌ Vulnerability database not found. Run `qip db update`.[/red]")
        return

    files = list(db_path.rglob("*"))
    total_size = sum(f.stat().st_size for f in files if f.is_file())
    console.print(f"[cyan]📦 Vulnerability Database[/cyan]")
    console.print(f"   Path:  {db_path}")
    console.print(f"   Files: {len(files)}")
    console.print(f"   Size:  {total_size / (1024*1024):.1f} MB")


# ─── qip agent ────────────────────────────────────────────────────────────────


@cli.group()
def agent():
    """Manage the Docker agent."""
    pass


@agent.command("build")
def agent_build():
    """Build the QIP agent Docker image."""
    config = load_config()
    from qip.docker_manager import DockerManager

    dm = DockerManager(config)
    if not dm.is_docker_running():
        console.print("[red]❌ Docker is not running.[/red]")
        sys.exit(1)

    project_root = Path(__file__).parent.parent.parent
    dm.build_image(project_root)


@agent.command("shell")
def agent_shell():
    """Open an interactive shell in the agent container (debug)."""
    import subprocess
    config = load_config()
    repo_path = find_repo_root()

    cmd = [
        "docker", "run", "-it", "--rm",
        "-v", f"{repo_path}:/repo:ro",
        "--entrypoint", "/bin/bash",
        config.agent.image,
    ]
    subprocess.run(cmd)


# ─── qip config ───────────────────────────────────────────────────────────────


@cli.group("config")
def config_cmd():
    """Manage QIP configuration."""
    pass


@config_cmd.command("show")
def config_show():
    """Print resolved configuration."""
    config = load_config()
    console.print_json(data=config.model_dump())


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
