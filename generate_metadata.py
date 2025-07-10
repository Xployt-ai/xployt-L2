import os
import json
import hashlib
import re
from pathlib import Path
from typing import Dict, Any

from dotenv import load_dotenv
from openai import OpenAI

# --------------------------
# Config / constants
# --------------------------
SELECTION_FILE = "vuln_files_selection.json"
OUTPUT_FILE = "vuln_file_metadata.json"
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

ENV_MAX_FILES = "METADATA_MAX_FILES"

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


def summarise_file(path: Path, client: OpenAI) -> str:
    """Call the LLM to get a 2-3 sentence summary."""
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            code = f.read(4000)  # send at most 4k chars to save tokens
    except Exception:
        code = ""

    prompt = (
        "You are a senior engineer. Summarise what the following file does in 2-3 "
        "sentences and mention any security-critical behaviour. Return only the summary." )

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a senior engineer."},
            {"role": "user", "content": prompt + "\n```\n" + code + "\n```"},
        ],
        temperature=0.2,
        max_tokens=120,
    )
    return response.choices[0].message.content.strip()


def load_selection() -> list[str]:
    with open(SELECTION_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("folders_to_analyze", []) + data.get("standalone_files", [])


def load_existing_metadata() -> Dict[str, Dict[str, Any]]:
    if not os.path.exists(OUTPUT_FILE):
        return {}
    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def main(base_dir: str = ".") -> None:
    load_dotenv()
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    # Resolve base directory: CLI arg takes precedence, otherwise env var CODEBASE_PATH, otherwise current dir.
    if base_dir == ".":
        env_base = os.getenv("CODEBASE_PATH")
        if env_base:
            base_dir = env_base

    paths = load_selection()
    # Optional limit from .env to process only a subset (useful for testing / cost control)
    max_files_raw = os.getenv(ENV_MAX_FILES)
    max_files: int | None = int(max_files_raw) if (max_files_raw and max_files_raw.isdigit()) else None

    if max_files is not None:
        print(f"⚙️  Limiting processing to first {max_files} files (METADATA_MAX_FILES)")
        paths = paths[:max_files]

    existing = load_existing_metadata()

    for rel_path in paths:
        full_path = Path(base_dir).joinpath(rel_path.lstrip("/\\"))
        if not full_path.exists():
            print(f"⚠️  Path missing: {full_path}")
            continue

        if full_path.is_dir():
            # For now just store minimal info; you could later aggregate child summaries
            entry = {
                "kind": "dir",
                "side": detect_side(full_path),
                "description": existing.get(rel_path, {}).get("description", ""),
            }
            existing[rel_path] = entry
            continue

        # --- file ---
        sha1 = sha1_file(full_path)
        prev = existing.get(rel_path, {})
        needs_summary = prev.get("sha1") != sha1 or "description" not in prev

        if needs_summary:
            description = summarise_file(full_path, client)
        else:
            description = prev["description"]

        contents = full_path.read_text(encoding="utf-8", errors="ignore")
        char_count = len(contents)

        entry = {
            "kind": "file",
            "side": detect_side(full_path),
            "language": detect_language(full_path),
            "loc": contents.count("\n") + 1,
            "imports": extract_imports(full_path),
            "description": description,
            "sha1": sha1,
            "token_estimate": estimate_tokens(char_count),
        }
        existing[rel_path] = entry
        print(f"✅ processed {rel_path}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)

    print(f"\n🎉 Metadata written to {OUTPUT_FILE} (total {len(existing)} entries)")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate/update per-file metadata summaries.")
    parser.add_argument("--base", default=".", help="Project root (defaults to cwd)")
    args = parser.parse_args()

    main(args.base)
