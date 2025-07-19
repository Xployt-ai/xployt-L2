from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
from pathlib import Path
import os
import sys
from typing import List
from dotenv import load_dotenv, set_key
import json

app = FastAPI(title="Xployt-L2 Pipeline Runner")

# Ordered list of pipeline scripts (relative to repo root)
SCRIPTS: List[str] = [
    "get_file_struct_json.py",
    "select_vuln_files.py",
    "generate_metadata.py",
    "group_subsets.py",
    "pipeline_suggester.py",
    "pipeline_executor.py",
]

class PipelineRequest(BaseModel):
    id: str
    path: str


def _ensure_dotenv() -> Path:
    """Ensure a .env file exists in the repo root and return its Path."""
    env_path = Path(".env")
    if not env_path.exists():
        env_path.touch()
    return env_path


def _update_env_vars(repo_id: str, codebase_path: str) -> None:
    """Persist env vars to .env and current process."""
    env_path = _ensure_dotenv()

    # Write to .env file
    set_key(str(env_path), "REPO_ID", repo_id)
    set_key(str(env_path), "CODEBASE_PATH", codebase_path)

    # Export to current process for child scripts
    os.environ["REPO_ID"] = repo_id
    os.environ["CODEBASE_PATH"] = codebase_path


def _run_script(script: str) -> subprocess.CompletedProcess[str]:
    """Run a python script and capture its stdout/stderr."""
    script_path = Path(script)
    if not script_path.exists():
        raise FileNotFoundError(f"Script '{script}' not found.")

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"

    return subprocess.run(
        [sys.executable, str(script_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        encoding="utf-8",
        errors="replace",
    )


@app.post("/run-pipeline")
async def run_pipeline(req: PipelineRequest):
    """Endpoint to run the pipeline sequentially, halting on failure."""
    # Step 1: update environment
    try:
        _update_env_vars(req.id, req.path)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to set env vars: {exc}")

    last_output = ""
    for script in SCRIPTS:
        print(f"\n▶ Running {script} …")
        proc = _run_script(script)
        last_output = proc.stdout
        # Echo first 300 chars to server console for quick insight
        preview = (last_output[:300] + "…") if len(last_output) > 300 else last_output
        print(f"✓ Finished {script} (exit {proc.returncode})\n--- output preview ---\n{preview}\n----------------------")
        if proc.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail={
                    "message": f"Script '{script}' failed (exit code {proc.returncode}).",
                    "output": last_output,
                },
            )

    # Try to return structured summary if pipeline_executor produced one
    summary_path = Path(os.environ["REPO_ID"] + "_data") / "pipeline_outputs" / "run_summary.json"
    if summary_path.exists():
        try:
            summary_json = json.loads(summary_path.read_text())
            return {"success": True, "results": summary_json}
        except Exception:
            # Fallback to raw output if JSON invalid
            pass

    return {"success": True, "output": last_output}


# Load .env on startup so other settings are available
load_dotenv()
