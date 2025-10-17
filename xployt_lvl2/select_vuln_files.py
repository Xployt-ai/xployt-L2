import os
import json
from pathlib import Path
# Third-party
from dotenv import load_dotenv
from openai import OpenAI
from utils.state_utils import data_dir as _data_dir
from xployt_lvl2.config.state import app_state, set_shortlisted_vul_files_count
from xployt_lvl2.config.settings import settings
import re
import traceback

load_dotenv()

# Directories to exclude from analysis
EXCLUDE_DIRS = {
    "node_modules", ".git", "dist", "build", "__pycache__", ".venv", ".idea", ".vscode", "coverage", "Archive"
}

# Central data directory
DATA_DIR = _data_dir()
DATA_DIR.mkdir(exist_ok=True)

# Maximum number of file paths to include in the LLM prompt.  
# SELECT_VUL_FILES_LIMIT = int(app_state.select_vul_files_limit, "30"))

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
    print("Running LLM filter (may be skipped if key missing)")

    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    if not client.api_key:
        print("OPENAI_API_KEY not set – skipping LLM filter.")
        return files

    SELECT_VUL_FILES_LIMIT = settings.select_vul_files_limit or 30
    # To control tokens, send at most first 400 file paths, then mention count.
    print(f"Sending {SELECT_VUL_FILES_LIMIT} files to LLM for filtering")
    head = files[:SELECT_VUL_FILES_LIMIT]
    remainder = len(files) - len(head)
    file_block = "\n".join(head)
    if remainder:
        file_block += f"\n… and {remainder} more files"

    # Use a verbose multiline prompt for clarity
    prompt = (
        "You are a senior application security engineer. Your task: review the list of file paths that follow and select ONLY those paths likely to hold vulnerabilities or configuration.\n\n"
        "Guidelines (follow ALL):\n"
        "1. INCLUDE: backend controllers, route handlers, services, DB models, authentication logic, env loaders, shell scripts, custom middleware.\n"
        "2. EXCLUDE: static assets, images, generated code, test files, docs (README / LICENSE / *.md), build artifacts.\n"
        "3. Return only the provided paths, focusing on the most risky ones.\n"
        "4. OUTPUT FORMAT: JSON array of strings ONLY – *no* keys, comments, or code fences. Do NOT wrap in triple backticks.\n"
        "5. EXACTLY reproduce the selected paths as they appear (do not modify slashes, case, etc.).\n\n"
        "Example output (for illustration only – do NOT repeat this text):\n"
        "[\n"
        "  \"backend/controllers/auth.js\",\n"
        "  \"backend/models/userModel.js\"\n"
        "]\n\n"
        "---\n"
        "FILES TO REVIEW:\n" + file_block
    )

    raw_content: str | None = None
    try:
        resp = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a senior security auditor."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        raw_content = resp.choices[0].message.content.strip()

        # Remove optional ```json fences the model may add despite instructions
        if raw_content.startswith("```"):
            raw_content = re.sub(r"^```json\s*|^```|```$", "", raw_content, flags=re.S).strip()

        selected = json.loads(raw_content)
        if isinstance(selected, list) and all(isinstance(x, str) for x in selected):
            print(f"LLM filter selected {len(selected)} files from {len(files)}")
            return selected
        else:
            raise ValueError("Response JSON is not a list of strings")
    except Exception as exc:
        print("LLM filtering failed – falling back to full list.")
        print("   Exception:")
        traceback.print_exception(type(exc), exc, exc.__traceback__)
        if raw_content is not None:
            print("   Raw LLM content →\n" + raw_content)
    print("Proceeding with unfiltered file list.")
    return files

def run(repo_id: str, codebase_path: str | Path) -> Path:
    """Pipeline step: select potentially vulnerable files and write JSON.

    Returns the path to the written JSON file.
    """

    file_structure = load_file_structure()
    print("Flattening file tree…")
    files_all = gather_all_files(file_structure, Path(codebase_path))

    # regex pre-filter
    files_regex = regex_pre_filter(files_all)

    # optional LLM filter
    files_final = filter_files_with_llm(files_regex)

    set_shortlisted_vul_files_count(repo_id, len(files_final))

    output = {"files_to_analyze": files_final}

    out_path = DATA_DIR / "vuln_files_selection.json"
    out_path.write_text(json.dumps(output, indent=2))
    print(f"Written selection JSON with {len(files_final)} files → {out_path}")
    return out_path

if __name__ == "__main__":
    repo_id = app_state.repo_id
    base_path = app_state.codebase_path
    
    if not base_path:
        raise RuntimeError("codebase_path env var must point to repo root.")
        
    run(repo_id, base_path)
