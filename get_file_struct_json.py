import os
import json

EXCLUDE_DIRS = {
    "node_modules", ".git", ".next", "dist", "build", "__pycache__",
    ".venv", ".idea", ".vscode", ".DS_Store", ".turbo", ".husky"
}

def build_file_tree(base_path, depth=4):
    file_structure = {}

    def recurse(current_path, current_depth):
        if current_depth > depth:
            return None
        tree = {}
        try:
            for entry in os.listdir(current_path):
                full_path = os.path.join(current_path, entry)
                if os.path.isdir(full_path):
                    if entry not in EXCLUDE_DIRS:
                        child_tree = recurse(full_path, current_depth + 1)
                        if child_tree is not None:
                            tree[entry] = child_tree
                else:
                    tree.setdefault("__files__", []).append(entry)
        except Exception as e:
            pass  # skip unreadable folders
        return tree if tree else None

    file_structure = recurse(base_path, 0)
    return file_structure

if __name__ == "__main__":
    # CHANGE THIS TO YOUR ABSOLUTE PATH
    base_path = os.getenv("CODEBASE_PATH")
    tree = build_file_tree(base_path, depth=6)
    
    # Output to a clean JSON
    with open("file_tree.json", "w", encoding="utf-8") as f:
        json.dump(tree, f, indent=2)

    print("✅ File structure saved to file_tree.json")
