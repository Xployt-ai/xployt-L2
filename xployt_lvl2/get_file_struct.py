import os
import sys, json
from dotenv import load_dotenv  
from pathlib import Path
from utils.state_utils import data_dir as _data_dir

load_dotenv()

EXCLUDED_DIRS = {
    "node_modules", ".git", "venv", "__pycache__", "build", "dist", ".next",
    ".turbo", "coverage", ".idea", ".vscode", "public", "static", ".env"
}

def print_tree(base_path, max_depth, prefix=""):
    if max_depth < 0:
        return

    try:
        entries = sorted(os.listdir(base_path))
    except PermissionError:
        return

    for index, entry in enumerate(entries):
        full_path = os.path.join(base_path, entry)
        if os.path.isdir(full_path) and entry not in EXCLUDED_DIRS:
            connector = "└── " if index == len(entries) - 1 else "├── "
            print(f"{prefix}{connector}{entry}/")
            extension = "    " if index == len(entries) - 1 else "│   "
            print_tree(full_path, max_depth - 1, prefix + extension)
        elif os.path.isfile(full_path):
            connector = "└── " if index == len(entries) - 1 else "├── "
            print(f"{prefix}{connector}{entry}")

if __name__ == "__main__":
    base_path = sys.argv[1] if len(sys.argv) > 1 else os.getenv("CODEBASE_PATH")
    if not base_path:
        print("Usage: poetry run python get_file_structure.py <path> [depth]")
        sys.exit(1)

    depth = int(sys.argv[2]) if len(sys.argv) > 2 else 3

    tree = print_tree(base_path, depth)
    
    data_dir = _data_dir()

    output_path = data_dir / "file_tree_printed.json"
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(tree, f, indent=2)

    print_tree(base_path, depth)
