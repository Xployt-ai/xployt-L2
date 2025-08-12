from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import io
import contextlib
from pathlib import Path
import os
import sys
from typing import List
import json
import asyncio
from sse_starlette.sse import EventSourceResponse  # type: ignore

app = FastAPI(title="Xployt-lvl2 Pipeline Runner")

# Ordered list of pipeline module names to import and execute.
# Each module should expose a `run(repo_id, codebase_path)` function. If the
# function is missing, we fall back to a `main()` callable.
PIPELINE_MODULES: List[str] = [
    "xployt_lvl2.get_file_struct_json",
    "xployt_lvl2.select_vuln_files",
    "xployt_lvl2.generate_metadata",
    "xployt_lvl2.group_subsets",
    "xployt_lvl2.pipeline_suggester",
    "xployt_lvl2.pipeline_executor",
]

class PipelineRequest(BaseModel):
    id: str
    path: str


from xployt_lvl2.config.settings import settings as _settings


def _update_env_vars(repo_id: str, codebase_path: str) -> None:
    """Update runtime settings"""

    # Update singleton settings (they are mutable via __dict__)
    _settings.repo_id = repo_id
    _settings.codebase_path = Path(codebase_path)

# ---------- Dynamic import helper ---------- #


def _call_pipeline_module(mod_name: str, repo_id: str, codebase_path: str) -> str:
    """Import *mod_name* and call its `run()` or `main()` entry point.

    Captures stdout for logging and returns it as a string.
    """
    import importlib

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        module = importlib.import_module(mod_name)

        # Prefer explicit run(repo_id, codebase_path)
        if hasattr(module, "run"):
            module.run(repo_id, codebase_path)
        else:
            raise AttributeError(f"Module '{mod_name}' has no run() entry point.")

    return buffer.getvalue()


@app.post("/run-pipeline")
async def run_pipeline(req: PipelineRequest):
    """Endpoint to run the pipeline sequentially, halting on failure."""
    # Step 1: update environment
    try:
        _update_env_vars(req.id, req.path)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to set env vars: {exc}")

    last_output = ""
    for mod in PIPELINE_MODULES:
        print(f"\n▶ Running {mod} …")
        try:
            last_output = _call_pipeline_module(mod, req.id, req.path)
            preview = (last_output[:300] + "…") if len(last_output) > 300 else last_output
            print(f"✓ Finished {mod}\n--- output preview ---\n{preview}\n----------------------")
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail={
                    "message": f"Step '{mod}' failed: {exc}",
                    "output": str(exc),
                },
            )

    # Try to return structured summary if pipeline_executor produced one
    summary_path = Path(_settings.repo_id + "_data") / "pipeline_outputs" / "run_summary.json"
    if summary_path.exists():
        try:
            summary_json = json.loads(summary_path.read_text())
            return {"success": True, "results": summary_json}
        except Exception:
            # Fallback to raw output if JSON invalid
            pass

    return {"success": True, "output": last_output}


# ---------- SSE generator ---------- #

async def _pipeline_sse_generator(req: "PipelineRequest"):
    """Async generator yielding progress events as SSE-compatible lines."""

    import json as _json

    def _yield(data: dict):
        """Return properly formatted SSE message string (EventSourceResponse will prepend)."""
        # EventSourceResponse adds the required  "data: " prefix and \n\n delimiter.
        return _json.dumps(data)

    try:
        _update_env_vars(req.id, req.path)
    except Exception as exc:
        yield _yield({"event": "error", "message": f"Failed to set env vars: {exc}"})
        return

    for mod in PIPELINE_MODULES:
        yield _yield({"event": "start", "step": mod})
        try:
            output = await asyncio.to_thread(_call_pipeline_module, mod, req.id, req.path)
            preview = (output[:300] + "…") if len(output) > 300 else output
            yield _yield({"event": "finish", "step": mod, "preview": preview})
        except Exception as exc:
            yield _yield({"event": "error", "step": mod, "message": str(exc)})
            return

    # On success, attempt to return summary path
    summary_path = Path(_settings.data_dir()) / "pipeline_outputs" / "run_summary.json"
    if summary_path.exists():
        yield _yield({"event": "complete", "summary_path": str(summary_path)})
    else:
        yield _yield({"event": "complete", "message": "Pipeline finished"})


# ---------- SSE Endpoint ---------- #

@app.post("/run-pipeline-sse")
async def run_pipeline_stream(req: "PipelineRequest"):
    """Endpoint that streams pipeline progress via Server-Sent Events (SSE)."""

    return EventSourceResponse(_pipeline_sse_generator(req))