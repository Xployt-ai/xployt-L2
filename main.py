from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
from pathlib import Path
import os
from typing import List
from dotenv import load_dotenv, set_key
import json

app = FastAPI(title="Xployt-L2 Pipeline Runner")

# Ordered list of pipeline scripts (relative to repo root)
SCRIPTS: List[str] = [
    "get_file_struct_json.py",
    "select_vuln_files.py",
    "generate_metadata.py",
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


def _update_env_vars(version: str, codebase_path: str) -> None:
    """Persist env vars to .env and current process."""
    env_path = _ensure_dotenv()

    # Write to .env file
    set_key(str(env_path), "VERSION", version)
    set_key(str(env_path), "CODEBASE_PATH", codebase_path)

    # Export to current process for child scripts
    os.environ["VERSION"] = version
    os.environ["CODEBASE_PATH"] = codebase_path


def _run_script(script: str) -> subprocess.CompletedProcess[str]:
    """Run a python script and capture its stdout/stderr."""
    script_path = Path(script)
    if not script_path.exists():
        raise FileNotFoundError(f"Script '{script}' not found.")

    return subprocess.run(
        ["python", str(script_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
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
        proc = _run_script(script)
        last_output = proc.stdout
        if proc.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail={
                    "message": f"Script '{script}' failed (exit code {proc.returncode}).",
                    "output": last_output,
                },
            )

    # Try to return structured summary if pipeline_executor produced one
    summary_path = Path(os.environ["VERSION"] + "_data") / "pipeline_outputs" / "run_summary.json"
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
