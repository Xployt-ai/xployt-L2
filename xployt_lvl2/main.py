import importlib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import io
import contextlib
from pathlib import Path
from typing import List
import json
import asyncio
import traceback
from sse_starlette.sse import EventSourceResponse  # type: ignore
from xployt_lvl2.utils.state_utils import data_dir as _data_dir
from xployt_lvl2.config.state import app_state, get_progress_state, reset_progress_state, get_metadata_files_count, get_subset_count, get_shortlisted_vul_files_count

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


def _update_env_vars(repo_id: str, codebase_path: str) -> None:
    """Update runtime settings"""

    # Update central app state
    app_state.repo_id = repo_id
    app_state.codebase_path = Path(codebase_path)


# ---------- Dynamic import helper ---------- #


def _call_pipeline_module(mod_name: str, repo_id: str, codebase_path: str) -> str:
    """Import *mod_name* and call its `run()` or `main()` entry point.

    Captures stdout for logging and returns it as a string.
    """

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        module = importlib.import_module(mod_name)

        # Prefer explicit run(repo_id, codebase_path)
        if hasattr(module, "run"):
            module.run(repo_id, codebase_path)
        else:
            raise AttributeError(f"Module '{mod_name}' has no run() entry point.")

    return buffer.getvalue()


# ---------- SSE generator ---------- #

async def _pipeline_sse_generator(req: "PipelineRequest"):
    """Async generator yielding uniform SSE JSON messages for pipeline progress.

    Payload schema (every message):
    {
      "progress": int,          # 0..100
      "status": str,            # "setting up" | "scanning" | "completed"
      "message": str,
      "vulnerabilities": list   # [] until final step (hook later)
    }
    """

    def _yield_uniform(progress: int, status: str, message: str, vulnerabilities: list | None = None):
        payload = {
            "progress": int(progress),
            "status": status,
            "message": message,
            "vulnerabilities": vulnerabilities if vulnerabilities is not None else [],
        }
        payload_json = json.dumps(payload)
        # Mirror to console at the same time
        print(payload_json, flush=True)
        return payload_json

    # Acquire or initialize per-repo progress state and reset fresh run
    reset_progress_state(req.id)
    state = get_progress_state(req.id)

    # Initial message
    yield _yield_uniform(0, "setting up", "Initializing pipeline")
    await asyncio.sleep(1)

    # Hardcoded step plan (except final distribution):
    # Map pipeline module -> (target_progress, status, message)
    step_plan: dict[str, tuple[int, str, str]] = {
        "xployt_lvl2.get_file_struct_json": (10, "scanning", "Analyzing file structure"),
        "xployt_lvl2.select_vuln_files": (20, "scanning", "Selecting potential vulnerable files"),
        "xployt_lvl2.generate_metadata": (30, "scanning", "Generating metadata"),
        "xployt_lvl2.group_subsets": (40, "scanning", "Grouping files into subsets"),
        "xployt_lvl2.pipeline_suggester": (55, "scanning", "Suggesting pipelines per subset"),
        # The final executor step will be spread dynamically to reach 100%
    }

    # Run through all modules except the last executor
    last_mod = PIPELINE_MODULES[-1] if PIPELINE_MODULES else None
    current_progress = 0
    for mod in PIPELINE_MODULES:
        if mod == last_mod:
            break
        target_progress, status, msg = step_plan.get(mod, (current_progress, "scanning", f"Running {mod}"))
        try:
            # Run in background
            task = asyncio.create_task(asyncio.to_thread(_call_pipeline_module, mod, req.id, req.path))

            # Determine incremental planning for specific modules
            if mod.endswith("generate_metadata"):
                steps = get_shortlisted_vul_files_count(req.id)
                delta = max(0, target_progress - current_progress)
                per = delta / max(1, steps)
                i = 0
                while not task.done() and i < steps:
                    next_progress = int(min(target_progress, round(current_progress + per * (i + 1))))
                    yield _yield_uniform(next_progress, status, "Generating metadata (per-file progress)")
                    i += 1
                    await asyncio.sleep(1)
                # Ensure task completion (propagate exceptions)
                await task
                current_progress = target_progress
                yield _yield_uniform(current_progress, status, msg)
                await asyncio.sleep(1)

            elif mod.endswith("pipeline_suggester"):
                steps = get_subset_count(req.id)
                delta = max(0, target_progress - current_progress)
                per = delta / max(1, steps)
                i = 0
                while not task.done() and i < steps:
                    next_progress = int(min(target_progress, round(current_progress + per * (i + 1))))
                    yield _yield_uniform(next_progress, status, f"Suggesting pipelines for subset {min(i+1, steps)}/{steps}")
                    i += 1
                    await asyncio.sleep(1)
                # Ensure task completion
                await task
                current_progress = target_progress
                yield _yield_uniform(current_progress, status, msg)
                await asyncio.sleep(1)

            else:
                # Generic heartbeat every 1s until completion
                while not task.done():
                    yield _yield_uniform(current_progress, status, msg)
                    await asyncio.sleep(1)
                await task
                current_progress = target_progress
                yield _yield_uniform(current_progress, status, msg)
                await asyncio.sleep(1)
        except Exception as exc:
            tb = traceback.format_exc()
            yield _yield_uniform(current_progress, "scanning", f"Step '{mod}' failed: {exc}\n{tb}")
            return

    # Final stage: dynamically spread remaining percentage across subsets
    if last_mod:
        # Determine subsets count using state/cache
        subset_count = state.subset_count

        remaining = max(0, 100 - current_progress)
        per_subset = remaining / max(1, subset_count)

        # Start executor in background
        exec_task = asyncio.create_task(asyncio.to_thread(_call_pipeline_module, last_mod, req.id, req.path))

        # Stream per-subset progress at 1s intervals
        for i in range(1, subset_count + 1):
            next_progress = int(min(100, round(current_progress + per_subset * i)))
            msg = f"Executing pipelines on subset {i}/{subset_count}"
            yield _yield_uniform(next_progress if i < subset_count else max(next_progress, 99), "scanning", msg)
            await asyncio.sleep(1)

        # If executor still running, keep 1s heartbeats at 99%
        while not exec_task.done():
            yield _yield_uniform(99, "scanning", "Finalizing pipeline execution")
            await asyncio.sleep(1)

        # Wait for executor to finish, then finalize
        try:
            await exec_task
        except Exception as exc:
            yield _yield_uniform(99, "scanning", f"Final stage failed: {exc}")
            return

    # Completed
    yield _yield_uniform(100, "completed", "Pipeline completed", vulnerabilities=[])


# ---------- SSE Endpoint ---------- #

@app.post("/run-pipeline-sse")
async def run_pipeline_stream(req: "PipelineRequest"):
    """Endpoint that streams pipeline progress via Server-Sent Events (SSE)."""

    try:
        _update_env_vars(req.id, req.path)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to set env vars: {exc}")

    # Reset progress state for this repo run
    reset_progress_state(req.id)

    return EventSourceResponse(_pipeline_sse_generator(req))


@app.post("/run-pipeline")
async def run_pipeline(req: PipelineRequest):
    """Endpoint to run the pipeline sequentially, halting on failure."""
    # Step 1: update environment
    try:
        _update_env_vars(req.id, req.path)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to set env vars: {exc}")

    # Reset progress state for this repo run
    reset_progress_state(req.id)

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
    summary_path = _data_dir() / "pipeline_outputs" / "run_summary.json"
    if summary_path.exists():
        try:
            summary_json = json.loads(summary_path.read_text())
            return {"success": True, "results": summary_json}
        except Exception:
            # Fallback to raw output if JSON invalid
            pass

    return {"success": True, "output": last_output}