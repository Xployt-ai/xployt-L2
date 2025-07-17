import os
import json
from pathlib import Path
# Third-party
from dotenv import load_dotenv
from openai import OpenAI
import re

load_dotenv()

# Directories to exclude from analysis
EXCLUDE_DIRS = {
    "node_modules", ".git", "dist", "build", "__pycache__", ".venv", ".idea", ".vscode", "coverage", "Archive"
}

# Central data directory
version = os.getenv("VERSION")
data_dir_name = f"{version}_data" if version else "data"
DATA_DIR = Path(data_dir_name)
DATA_DIR.mkdir(exist_ok=True)

# Maximum number of file paths to include in the LLM prompt.  
SELECT_VUL_FILES_LIMIT = int(os.getenv("SELECT_VUL_FILES_LIMIT", "30"))

def load_file_structure(file_path=DATA_DIR / "file_tree.json"):
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

# ---------------------------
# Utility to flatten tree
# ---------------------------

def recurse_tree(tree: dict, cwd: Path, out: list[str]):
    """Walk nested dict produced by get_file_struct_json.build_file_tree."""
    for key, val in tree.items():
        if key == "__files__":
            for fname in val:
                out.append(str(cwd / fname))
            continue
        if key in EXCLUDE_DIRS:
            continue
        if isinstance(val, dict):
            recurse_tree(val, cwd / key, out)

def gather_all_files(file_structure: dict, base_path: Path) -> list[str]:
    files: list[str] = []
    recurse_tree(file_structure, base_path, files)
    # normalise path separators
    files = [p.replace("\\", "/") for p in files]
    print(f"🔍 gather_all_files: collected {len(files)} paths before filtering")
    return files

# ---------------------------
# Regex pre-filter
# ---------------------------

# Patterns of files to EXCLUDE (tests, docs, assets)
EXCLUDE_REGEX = re.compile(
    r"(?i)(\.test\.|\.spec\.|\.mock\.|/tests?/|/__tests__/|README|LICENSE|\.md$|\.png$|\.jpg$|\.jpeg$|\.gif$|\.svg$|\.ico$|\.lock$|yarn\.lock|package-lock\.json|\.map$|\.snap$|\.log$|/fixtures?/|\.sample\.|\.css$|\.scss$|\.less$)"
)

def regex_pre_filter(files: list[str]) -> list[str]:
    filtered = [f for f in files if not EXCLUDE_REGEX.search(f)]
    print(f"🔧 regex_pre_filter: kept {len(filtered)}/{len(files)} files after regex exclusions")
    return filtered

# ---------------------------
# LLM filtering
# ---------------------------

def filter_files_with_llm(files: list[str]) -> list[str]:
    """Ask the LLM to pick only files likely to contain security-relevant logic."""
    print("⚙️  Running LLM filter (may be skipped if key missing)")

    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    if not client.api_key:
        print("⚠️  OPENAI_API_KEY not set – skipping LLM filter.")
        return files

    # To control tokens, send at most first 400 file paths, then mention count.
    print(f"ℹ️  Sending {SELECT_VUL_FILES_LIMIT} files to LLM for filtering")
    head = files[:SELECT_VUL_FILES_LIMIT]
    remainder = len(files) - len(head)
    file_block = "\n".join(head)
    if remainder:
        file_block += f"\n… and {remainder} more files"

    prompt = (
        "As a senior application security engineer, your task is to review the following file paths from a MERN-stack project and select only those that are likely to contain security-sensitive code or configurations. "
        "Focus on identifying backend controllers, route handlers, services, database models, authentication logic, environment loaders, shell scripts, and custom middleware as potential areas of interest. "
        "Strictly avoid static assets, images, generated code, test files, README, license, and build artifacts. "
        "Provide a JSON array of the chosen file paths (exact strings). "
        "Aim to list between 5% and 30% of the files, prioritizing those most likely to contain vulnerabilities.\n\n"
        "Files:\n" + file_block
    )

    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a senior security auditor."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            # max_tokens=300,
        )
        content = resp.choices[0].message.content.strip()
        selected = json.loads(content)
        if isinstance(selected, list) and all(isinstance(x, str) for x in selected):
            print(f"✅ LLM filter selected {len(selected)} files from {len(files)}")
            return selected
    except Exception:
        pass  # fall back
    print("⚠️  LLM filtering failed – keeping all files.")
    return files

if __name__ == "__main__":
    base_path_env = os.getenv("CODEBASE_PATH")
    if not base_path_env:
        raise RuntimeError("CODEBASE_PATH env var must point to repo root.")

    file_tree = load_file_structure()

    print("📂 Flattening file tree…")
    files_all = gather_all_files(file_tree, Path(base_path_env))

    # 1️⃣ regex pre-filter
    files_regex = regex_pre_filter(files_all)

    # 2️⃣ optional LLM filter
    files_final = filter_files_with_llm(files_regex)

    output = {"files_to_analyze": files_final}

    out_path = DATA_DIR / "vuln_files_selection.json"
    out_path.write_text(json.dumps(output, indent=2))
    print(f"💾 Written selection JSON with {len(files_final)} files → {out_path}")
