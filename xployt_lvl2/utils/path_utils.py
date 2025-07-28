from pathlib import Path
from xployt_lvl2.config.settings import settings as _settings
import os

__all__ = ["data_dir"]

def data_dir() -> Path:
    """Return the base directory where all generated artifacts are stored.

    Structure: output/<repo_id>_data  (or output/data if repo_id is not set)
    Ensures both the parent `output/` and the repo_ided sub-directory exist.
    """
    repo_id = _settings.repo_id
    root = Path("output")
    root.mkdir(exist_ok=True)

    dir_name = f"{repo_id}_data" if repo_id else "data"
    path = root / dir_name
    path.mkdir(exist_ok=True)
    return path
