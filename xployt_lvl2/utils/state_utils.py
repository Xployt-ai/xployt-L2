from pathlib import Path
from xployt_lvl2.config.state import app_state
import os
import json
from dataclasses import dataclass

__all__ = [
    "data_dir",
]

def data_dir() -> Path:
    """Return the base directory where all generated artifacts are stored.

    Structure: output/<repo_id>_data  (or output/data if repo_id is not set)
    Ensures both the parent `output/` and the repo_ided sub-directory exist.
    """
    repo_id = app_state.repo_id
    root = Path("output")
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
