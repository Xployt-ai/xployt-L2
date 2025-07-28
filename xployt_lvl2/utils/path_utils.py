from pathlib import Path
import os

__all__ = ["data_dir"]

def data_dir() -> Path:
    """Return the base directory where all generated artifacts are stored.

    Structure: output/<REPO_ID>_data  (or output/data if REPO_ID not set)
    Ensures both the parent `output/` and the repo_ided sub-directory exist.
    """
    repo_id = os.getenv("REPO_ID")
    root = Path("output")
    root.mkdir(exist_ok=True)

    dir_name = f"{repo_id}_data" if repo_id else "data"
    path = root / dir_name
    path.mkdir(exist_ok=True)
    return path
