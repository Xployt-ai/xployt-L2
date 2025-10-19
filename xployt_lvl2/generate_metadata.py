import os
import json
import hashlib
import re
from pathlib import Path
from typing import Dict, Any, Tuple
from xployt_lvl2.utils.state_utils import data_dir as _data_dir
from openai import OpenAI
from xployt_lvl2.config.settings import settings as _settings
from xployt_lvl2.config.state import app_state
from xployt_lvl2.utils.state_utils import get_vuln_files_metadata_file, get_vuln_files_selection_file

# --------------------------
# Config / constants
# --------------------------
BACKEND_ANCHOR = os.sep + "backend" + os.sep
FRONTEND_ANCHOR = os.sep + "frontend" + os.sep

EXT_TO_LANG = {
    ".js": "js",
    ".jsx": "jsx",
    ".ts": "ts",
    ".tsx": "tsx",
    ".py": "python",
    ".json": "json",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".html": "html",
    ".css": "css",
}

IMPORT_REGEX = re.compile(r"^(?:import|from)\s+([\w\.\/\-@]+)")
TOKEN_CHARS_PER_TOKEN = 4  # very rough approximation for GPT-style models

def sha1_file(path: Path) -> str:
    """Return SHA-1 hash of a file (hex)."""
    h = hashlib.sha1()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_side(path: Path) -> str:
    p = str(path)
    if BACKEND_ANCHOR in p:
        return "backend"
    if FRONTEND_ANCHOR in p:
        return "frontend"
    return "unknown"


def detect_language(path: Path) -> str:
    return EXT_TO_LANG.get(path.suffix.lower(), path.suffix.lstrip("."))


def extract_imports(path: Path, max_lines: int = 100) -> list[str]:
    """Parse first *max_lines* for import statements (js/py style)."""
    imports = []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for _ in range(max_lines):
                line = f.readline()
                if not line:
                    break
                m = IMPORT_REGEX.match(line.strip())
                if m:
                    imports.append(m.group(1))
    except Exception:
        pass  # binary or unreadable
    return imports


def estimate_tokens(char_count: int) -> int:
    return int(char_count / TOKEN_CHARS_PER_TOKEN) + 1


def summarise_and_imports(path: Path, client: OpenAI) -> Tuple[str, list[str]]:
    """Ask the LLM for a JSON object containing summary and list of imports."""
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            code = f.read(4000)
    except Exception:
        code = ""

    prompt = (
        "You are a senior software security engineer. Given the following source code, "
        "produce a concise 2-3 sentence summary highlighting what the file does and any "
        "security-critical behaviour. Additionally, extract a JSON array named 'imports' "
        "containing the names of all modules/packages that the file explicitly imports. "
        "Return STRICTLY a JSON object with keys 'summary' and 'imports'.\n\nCode:\n```\n"
        + code + "\n```"
    )

    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a senior engineer."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=200,
        )
        content = resp.choices[0].message.content.strip()
        data = json.loads(content)
        summary = data.get("summary", "")
        imports = data.get("imports", [])
        if isinstance(summary, str) and isinstance(imports, list):
            imports = [str(i) for i in imports]
            return summary, imports
    except Exception:
        pass  # will fall back

    # Fallback: separate extraction
    return summarise_file(path, client), extract_imports(path)


# Retain original summarise_file for fallback purposes
def summarise_file(path: Path, client: OpenAI) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            code = f.read(4000)
    except Exception:
        code = ""

    prompt = (
        "You are a senior engineer. Summarise what the following file does in 2-3 sentences, "
        "mentioning any security-critical behaviour. Return ONLY the summary text."
    )

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a senior engineer."},
            {"role": "user", "content": prompt + "\n```\n" + code + "\n```"},
        ],
        temperature=0.2,
        max_tokens=120,
    )
    return resp.choices[0].message.content.strip()


def load_selection() -> list[str]:
    with open(get_vuln_files_selection_file(), "r", encoding="utf-8") as f:
        data = json.load(f)
    if "files_to_analyze" in data:
        return data["files_to_analyze"]
    # legacy format
    return data.get("folders_to_analyze", []) + data.get("standalone_files", [])


def load_existing_metadata() -> Dict[str, Dict[str, Any]]:
    if not get_vuln_files_metadata_file().exists():
        return {}
    with get_vuln_files_metadata_file().open("r", encoding="utf-8") as f:
        print(f"Loading existing metadata from {get_vuln_files_metadata_file()}")
        return json.load(f)


def _generate_metadata(base_dir: str) -> None:
    """Core implementation – assumes settings/client have been prepared."""
    client = OpenAI(api_key=_settings.openai_api_key)

    # Load initial selection (folders + files) and expand folders to individual files
    raw_paths = load_selection()
    paths: list[str] = []

    for p in raw_paths:
        full = Path(base_dir).joinpath(p.lstrip("/\\"))
        if full.is_dir():
            for child in full.rglob("*"):
                if child.is_file():
                    rel_child = str(child.relative_to(base_dir)).replace("\\", "/")
                    paths.append(rel_child)
        else:
            paths.append(p)

    # Deduplicate while preserving order
    seen_set = set()
    paths = [x for x in paths if not (x in seen_set or seen_set.add(x))]

    # Optional limit to process only a subset (useful for testing / cost control)
    max_files = _settings.metadata_max_files

    if max_files is not None:
        print(f"Limiting processing to first {max_files} files (_settings.metadata_max_files)")
        paths = paths[:max_files]

    # Publish the distinct file count for progress tracking
    try:
        set_metadata_files_count(app_state.repo_id, len(paths))
    except Exception:
        pass

    existing = load_existing_metadata()

    for rel_path in paths:
        full_path = Path(base_dir).joinpath(rel_path.lstrip("/\\"))
        if not full_path.exists():
            print(f"Path missing: {full_path}")
            continue

        if full_path.is_dir():
            # Skip directory entries now; they were expanded to files earlier
            continue

        # --- file ---
        sha1 = sha1_file(full_path)
        prev = existing.get(rel_path, {})
        needs_summary = prev.get("sha1") != sha1 or "description" not in prev

        if needs_summary:
            description, imports = summarise_and_imports(full_path, client)
        else:
            print(f"Skipping {rel_path} (no changes detected)")
            description = prev["description"]
            imports = prev.get("imports", extract_imports(full_path))

        contents = full_path.read_text(encoding="utf-8", errors="ignore")
        char_count = len(contents)

        entry = {
            "kind": "file",
            "side": detect_side(full_path),
            "language": detect_language(full_path),
            "loc": contents.count("\n") + 1,
            "imports": imports,
            "description": description,
            "sha1": sha1,
            "token_estimate": estimate_tokens(char_count),
        }
        existing[rel_path] = entry
        print(f"✅ processed {rel_path}")

    with get_vuln_files_metadata_file().open("w", encoding="utf-8") as f:
        print(f"Writing metadata to {get_vuln_files_metadata_file()}")
        json.dump(existing, f, indent=2)

    print(f"Metadata written to {get_vuln_files_metadata_file()} (total {len(existing)} entries)")


# ---------- Public API ---------- #


def run(repo_id: str | None = None, codebase_path: str | Path | None = None) -> Path:
    """Pipeline step entry. Uses settings values by default."""
    if repo_id is not None:
        app_state.repo_id = repo_id
    if codebase_path is not None:
        app_state.codebase_path = Path(codebase_path)
    _generate_metadata(str(app_state.codebase_path))
    return get_vuln_files_metadata_file()

if __name__ == "__main__":
    run()
