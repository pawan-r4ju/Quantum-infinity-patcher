"""FastAPI review server — local web UI for patch review."""

from __future__ import annotations

import json
import webbrowser
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from rich.console import Console

from qip.models import Patch, PatchStatus

console = Console()

# ─── FastAPI App ──────────────────────────────────────────────────────────────

app = FastAPI(title="QIP Review", version="0.1.0")

# Global state for the review session
_review_state: dict = {
    "run_id": None,
    "patches": [],
    "report": {},
    "scan_dir": None,
}


class ReviewAction(BaseModel):
    patch_id: str
    action: str  # approve | reject | skip
    edited_diff: Optional[str] = None


class ReviewSummary(BaseModel):
    run_id: str
    total: int
    approved: int
    rejected: int
    pending: int


# ─── API Routes ───────────────────────────────────────────────────────────────


@app.get("/api/status")
def get_status():
    """Get current review session status."""
    patches = _review_state["patches"]
    return {
        "run_id": _review_state["run_id"],
        "total": len(patches),
        "approved": sum(1 for p in patches if p.get("review_status") == "approved"),
        "rejected": sum(1 for p in patches if p.get("review_status") == "rejected"),
        "pending": sum(1 for p in patches if p.get("review_status") == "pending"),
    }


@app.get("/api/patches")
def get_patches():
    """Get all patches for review."""
    return _review_state["patches"]


@app.get("/api/patches/{patch_id}")
def get_patch(patch_id: str):
    """Get a specific patch."""
    for p in _review_state["patches"]:
        if p["patch_id"] == patch_id:
            return p
    raise HTTPException(status_code=404, detail="Patch not found")


@app.post("/api/review")
def submit_review(action: ReviewAction):
    """Submit a review action for a patch."""
    for p in _review_state["patches"]:
        if p["patch_id"] == action.patch_id:
            if action.action in ("approve", "reject", "skip"):
                p["review_status"] = action.action if action.action != "skip" else "pending"
                if action.edited_diff:
                    p["diff_content"] = action.edited_diff
                    p["review_status"] = "edited"

                # Save state
                _save_review_state()
                return {"ok": True, "patch_id": action.patch_id, "status": p["review_status"]}
            raise HTTPException(status_code=400, detail=f"Invalid action: {action.action}")
    raise HTTPException(status_code=404, detail="Patch not found")


@app.post("/api/batch")
def batch_action(action: str, min_confidence: str = "high"):
    """Batch approve/reject patches by confidence level."""
    confidence_order = ["high", "medium", "low"]
    threshold_idx = confidence_order.index(min_confidence) if min_confidence in confidence_order else 0

    count = 0
    for p in _review_state["patches"]:
        if p["review_status"] != "pending":
            continue
        p_confidence = p.get("confidence", "low")
        p_idx = confidence_order.index(p_confidence) if p_confidence in confidence_order else 2
        if p_idx <= threshold_idx:
            p["review_status"] = action
            count += 1

    _save_review_state()
    return {"ok": True, "affected": count}


@app.get("/api/report")
def get_report():
    """Get the full scan report."""
    return _review_state["report"]


# ─── Static Files (Web UI) ───────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
def serve_ui():
    """Serve the review UI."""
    web_dir = Path(__file__).parent.parent.parent / "web"
    index_path = web_dir / "index.html"
    if index_path.exists():
        return HTMLResponse(content=index_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>QIP Review UI</h1><p>Web files not found.</p>")


# ─── Session Management ───────────────────────────────────────────────────────


def load_review_session(scan_dir: Path, run_id: str) -> None:
    """Load a scan run into the review session."""
    _review_state["run_id"] = run_id
    _review_state["scan_dir"] = str(scan_dir)

    # Load report.json
    report_path = scan_dir / "report.json"
    if report_path.exists():
        with open(report_path, "r", encoding="utf-8") as f:
            _review_state["report"] = json.load(f)

    # Load patches
    patches_dir = scan_dir / "patches"
    patches = []
    if patches_dir.exists():
        for patch_file in sorted(patches_dir.glob("*.patch")):
            meta_file = patch_file.with_suffix(".json")
            if meta_file.exists():
                with open(meta_file, "r", encoding="utf-8") as f:
                    meta = json.load(f)
            else:
                meta = {"patch_id": patch_file.stem, "cve_id": patch_file.stem}

            meta["diff_content"] = patch_file.read_text(encoding="utf-8")
            meta["patch_file"] = patch_file.name
            meta.setdefault("review_status", "pending")
            patches.append(meta)

    # Check for existing review state
    state_file = scan_dir / "review_state.json"
    if state_file.exists():
        with open(state_file, "r", encoding="utf-8") as f:
            saved = json.load(f)
            # Restore review statuses
            saved_map = {p["patch_id"]: p["review_status"] for p in saved}
            for p in patches:
                if p["patch_id"] in saved_map:
                    p["review_status"] = saved_map[p["patch_id"]]

    _review_state["patches"] = patches


def _save_review_state() -> None:
    """Persist review state to disk."""
    scan_dir = _review_state.get("scan_dir")
    if not scan_dir:
        return
    state_file = Path(scan_dir) / "review_state.json"
    with open(state_file, "w", encoding="utf-8") as f:
        json.dump(_review_state["patches"], f, indent=2)

    # Copy approved patches to approved/ directory
    approved_dir = Path(scan_dir).parent.parent / "approved"
    approved_dir.mkdir(parents=True, exist_ok=True)
    patches_dir = Path(scan_dir) / "patches"

    for p in _review_state["patches"]:
        if p["review_status"] in ("approved", "edited"):
            src = patches_dir / p["patch_file"]
            if src.exists():
                dst = approved_dir / p["patch_file"]
                dst.write_text(
                    p.get("diff_content", src.read_text(encoding="utf-8")),
                    encoding="utf-8",
                )


def start_review_server(
    scan_dir: Path,
    run_id: str,
    host: str = "127.0.0.1",
    port: int = 8500,
    open_browser: bool = True,
) -> None:
    """Start the review server."""
    import uvicorn

    load_review_session(scan_dir, run_id)

    console.print(f"[cyan]🔍 Review server starting...[/cyan]")
    console.print(f"   URL: http://{host}:{port}")
    console.print(f"   Run: {run_id}")
    console.print(f"   Patches: {len(_review_state['patches'])}")
    console.print("")
    console.print("[dim]Press Ctrl+C to stop[/dim]")

    if open_browser:
        webbrowser.open(f"http://{host}:{port}")

    uvicorn.run(app, host=host, port=port, log_level="warning")
