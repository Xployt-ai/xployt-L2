from pathlib import Path
from xployt_lvl2.config.state import app_state
import os
import json
from dataclasses import dataclass

__all__ = [
    "data_dir",
]

def get_pipelines_file():
    """Get the current pipelines file path"""
    return Path(__file__).resolve().parent.parent / "config" / "pipelines.json"

def get_file_struct_json():
    """Get the current file struct json file path"""
    return get_data_dir() / "file_struct.json"
    
def get_vuln_files_selection_file():
    """Get the current selection file path"""
    return get_data_dir() / "vuln_files_selection.json"

def get_vuln_files_metadata_file():
    """Get the current output file path"""
    return get_data_dir() / "vuln_file_metadata.json"

def get_data_dir():
    """Get the current data directory based on app_state.repo_id"""
    return data_dir()

def get_subset_file():
    """Get the current subset file path"""
    return get_data_dir() / "file_subsets.json"

def get_suggestions_file():
    """Get the current suggestions file path"""
    return get_data_dir() / "subset_pipeline_suggestions.json"

def get_output_dir():
    """Get the current output directory and ensure it exists"""
    output_dir = get_data_dir() / "pipeline_outputs"
    output_dir.mkdir(exist_ok=True)
    return output_dir

def data_dir() -> Path:
    """Return the base directory where all generated artifacts are stored.

    Structure: <scanner_root>/output/<repo_id>_data
    Always creates output inside the scanner's codebase for deterministic behavior.
    """
    # Get the scanner's root directory (xployt_lvl2 project root)
    scanner_root = Path(__file__).resolve().parent.parent.parent
    repo_id = app_state.repo_id
    
    # Create output directory inside the scanner's codebase
    root = scanner_root / "output"
    root.mkdir(exist_ok=True)

    dir_name = f"{repo_id}_data" if repo_id else "data"
    path = root / dir_name
    path.mkdir(exist_ok=True)
    return path

def _safe_read_json(path: Path):
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None

def _expand_selection_to_files(base_dir: str, selection_obj: dict | list) -> list[str]:
    raw_paths: list[str] = []
    if isinstance(selection_obj, dict):
        if "files_to_analyze" in selection_obj:
            raw_paths = selection_obj.get("files_to_analyze", [])
        else:
            raw_paths = selection_obj.get("folders_to_analyze", []) + selection_obj.get("standalone_files", [])
    elif isinstance(selection_obj, list):
        raw_paths = [str(p) for p in selection_obj]

    paths: list[str] = []
    for p in raw_paths:
        full = Path(base_dir).joinpath(str(p).lstrip("/\\"))
        if full.is_dir():
            for child in full.rglob("*"):
                if child.is_file():
                    rel_child = str(child.relative_to(base_dir)).replace("\\", "/")
                    paths.append(rel_child)
        else:
            paths.append(str(p))

    seen: set[str] = set()
    dedup = [x for x in paths if not (x in seen or seen.add(x))]
    return dedup
