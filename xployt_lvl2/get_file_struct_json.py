import os
import json
from pathlib import Path
from xployt_lvl2.config.settings import settings as _settings
from utils.path_utils import data_dir as _data_dir

EXCLUDE_DIRS = {
    "node_modules", ".git", ".next", "dist", "build", "__pycache__",
    ".venv", ".idea", ".vscode", ".DS_Store", ".turbo", ".husky"
}

# ----------------------
# Public API
# ----------------------

def generate_file_tree(base_path: str | Path, depth: int = 4) -> dict | None:
    """Return nested dict representing the file tree rooted at *base_path*.

    Folders listed in *EXCLUDE_DIRS* are skipped. Depth controls recursion level.
    Returns *None* if base_path is unreadable.
    """

    base_path = Path(base_path)
    if not base_path.exists():
        raise FileNotFoundError(f"Base path '{base_path}' does not exist.")

    def _recurse(current_path: Path, current_depth: int):
        if current_depth > depth:
            return None
        tree: dict[str, dict] = {}
        try:
            for entry in os.listdir(current_path):
                full_path = current_path / entry
                if full_path.is_dir():
                    if entry not in EXCLUDE_DIRS:
                        child_tree = _recurse(full_path, current_depth + 1)
                        if child_tree is not None:
                            tree[entry] = child_tree
                else:
                    tree.setdefault("__files__", []).append(entry)
        except Exception:
            # skip unreadable folders/files
            return None
        return tree if tree else None

    return _recurse(base_path, 0)


def run(repo_id: str, codebase_path: str | Path, depth: int = 6) -> Path:
    """Generate file structure JSON and write it under the central data directory.

    Returns the path to the written JSON file.
    """
    tree = generate_file_tree(codebase_path, depth=depth)
    if tree is None:
        raise RuntimeError("Unable to generate file tree; result is empty.")

    data_dir = _data_dir()
    output_path = data_dir / "file_tree.json"
    output_path.write_text(json.dumps(tree, indent=2))
    return output_path

if __name__ == "__main__":
    # CHANGE THIS TO YOUR ABSOLUTE PATH
    base_path = _settings.codebase_path
    repo_id = _settings.repo_id
    try:
        out = run(repo_id, base_path, depth=6)
        print(f"✅ File structure saved to {out}")
    except Exception as exc:
        print(f"❌ Failed to generate file structure: {exc}")
