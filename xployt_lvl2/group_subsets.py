import json
from pathlib import Path
from typing import List
from utils.state_utils import data_dir as _data_dir
from xployt_lvl2.config.state import set_subset_count
from xployt_lvl2.config.settings import settings as _settings
from xployt_lvl2.config.state import app_state
from openai import OpenAI
import re

DATA_DIR = _data_dir()
METADATA_FILE = DATA_DIR / "vuln_file_metadata.json"
OUTPUT_FILE = DATA_DIR / "file_subsets.json"

# Max files to include in each LLM prompt chunk to avoid context overflow
MAX_FILES_IN_PROMPT = 60

def load_metadata() -> dict[str, dict]:
    if not METADATA_FILE.exists():
        raise FileNotFoundError(
            f"{METADATA_FILE} missing - run generate_metadata.py first")
    with METADATA_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)


def build_llm_prompt(meta: dict[str, dict]) -> str:
    """Compose the prompt listing files and their summaries."""
    lines = []
    for idx, (path, info) in enumerate(meta.items()):
        if info.get("kind") != "file":
            continue
        if idx >= MAX_FILES_IN_PROMPT:
            break
        summary = info.get("description", "")
        side = info.get("side", "")
        lang = info.get("language", "")
        imports = ", ".join(info.get("imports", [])[:5])  # Show first 5 imports max
        if imports:
            lines.append(f"- {path} [{side}/{lang}]: {summary} | Imports: {imports}")
        else:
            lines.append(f"- {path} [{side}/{lang}]: {summary}")
    if len(meta) > MAX_FILES_IN_PROMPT:
        print(f"Omitted {len(meta) - MAX_FILES_IN_PROMPT} files for brevity")
        lines.append(f"… {len(meta) - MAX_FILES_IN_PROMPT} more files omitted for brevity …")

    instructions = (
        "You are a senior full-stack architect specializing in security reviews of MERN stack applications. "
        "Group the following files into logical subsets based on their functional connections. Focus specifically on:\n\n"
        "1. End-to-end data flows (Frontend → Backend → DB → Response)\n"
        "2. MVC relationships (Controller ↔ Model ↔ DB-Schema)\n"
        "3. Shared state, props, session usage, or token verification\n"
        "4. Authentication and authorization flows\n"
        "5. API endpoints and their handlers\n\n"
        "Guidelines:\n"
        "- Each subset should represent a complete functional unit or data flow\n"
        "- Include both frontend and backend files that work together in the same subset\n"
        "- Group files that share security contexts (e.g., authentication logic)\n"
        "- Aim for 5-15 files per subset (though this can vary)\n"
        "- Every file should be in at least one subset\n\n"
        "Return ONLY a JSON array where each element has the exact schema below. Do NOT include any surrounding prose, explanations, or markdown fences. Return raw JSON only.\n\n"
        "Schema (exact keys and types):\n"
        "- subset_id: string (e.g. 'subset-001')\n"
        "- file_paths: array of strings (each item must be an exact file path listed in the Files section)\n"
        "- reason: string (a single paragraph explaining why these files belong together)\n\n"
        "Example (must match this structure exactly):\n"
        "[\n"
        "  {\n"
        "    \"subset_id\": \"subset-001\",\n"
        "    \"file_paths\": [\"E:/path/to/frontend/login.jsx\", \"E:/path/to/backend/authController.js\"],\n"
        "    \"reason\": \"End-to-end login flow: frontend form, backend auth controller, and session/token creation.\"\n"
        "  }\n"
        "]\n\n"
        "Important rules:\n"
        "- Do NOT wrap the JSON in markdown fences (```).\n"
        "- Do NOT add any text before or after the JSON.\n"
        "- Each file listed under file_paths must exactly match a path from the Files list.\n"
        "- Keep subset_id values unique within this response.\n"
    )

    return instructions + "\n\nFiles:\n" + "\n".join(lines)


def _ask_llm_for_grouping_chunk(chunk_meta: dict[str, dict], offset: int) -> list[dict] | None:
    """Call OpenAI to propose subsets. Returns list on success, else None."""
    api_key = _settings.openai_api_key
    if not api_key:
        print("OPENAI_API_KEY not set - cannot use LLM grouping")
        return None

    client = OpenAI(api_key=api_key)
    prompt = build_llm_prompt(chunk_meta)
    print("Asking LLM to group files based on functional connections...")

    try:
        response = client.chat.completions.create(
            model=_settings.llm_model_for_subset_grouping, 
            messages=[
                {"role": "system", "content": "You are a senior security auditor. Return ONLY valid JSON array output with no additional text."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=1500,
        )
        content = response.choices[0].message.content.strip()
        print("Received response from LLM")
        
        # Clean up the response by removing markdown code fences and other formatting
        # Check for markdown code blocks (```json or ``` at start/end)
        if content.startswith('```'):
            # Find the end of the first line containing the opening fence
            first_newline = content.find('\n')
            if first_newline != -1:
                # Remove the opening fence line (```json)
                content = content[first_newline + 1:]
            
            # Remove closing code fence if present
            if '```' in content:
                content = content.rsplit('```', 1)[0].strip()
        
        # Attempt to parse the JSON
        try:
            subsets = json.loads(content)
            
            # Ensure unique subset ids by offsetting
            for s in subsets:
                orig_id = s.get("subset_id", "subset")
                s["subset_id"] = f"{orig_id}-chunk{offset:02d}"
            return subsets
        except Exception as e:
            print(f"JSON parsing error: {str(e)}")
            # Debug: print a snippet of the response for diagnosis
            print(f"Response snippet: {content[:500]}...")
            return None
        
        print("LLM response was not a valid subset array format")
    except Exception as e:
        # Parsing or API error
        print(f"Error during LLM grouping: {str(e)}")
        # Debug: print a snippet of the response for diagnosis
        if 'content' in locals():
            print(f"Response snippet: {content}")
        return None

    return None


def ask_llm_for_grouping(meta: dict[str, dict]) -> list[dict] | None:
    """Orchestrator: splits metadata into manageable chunks and merges results."""
    items = list(meta.items())
    all_subsets: list[dict] = []
    chunk_index = 0
    while items:
        chunk_pairs = items[:MAX_FILES_IN_PROMPT]
        items = items[MAX_FILES_IN_PROMPT:]
        chunk_meta = dict(chunk_pairs)
        chunk_index += 1
        print(f"Processing chunk {chunk_index} with {len(chunk_meta)} files…")
        subsets = _ask_llm_for_grouping_chunk(chunk_meta, chunk_index)
        if not subsets:
            print("LLM returned no data for this chunk; aborting.")
            return None
        all_subsets.extend(subsets)

    # Renumber subset_ids sequentially (subset-001, subset-002 …)
    for idx, sub in enumerate(all_subsets, start=1):
        sub["subset_id"] = f"subset-{idx:03d}"

    return all_subsets


def main():
    meta = load_metadata()

    try:
        # Try LLM-powered grouping with chunking
        subsets = ask_llm_for_grouping(meta)
        
        if not subsets:
            raise RuntimeError(
                "LLM grouping returned no data. Ensure OPENAI_API_KEY is set and the LLM prompt is correct."
            )
    except Exception as e:
        print(f"\nEncountered error during subset grouping: {str(e)}")
        raise

    OUTPUT_FILE.write_text(json.dumps(subsets, indent=2))
    # Publish subset count for progress tracking
    try:
        set_subset_count(app_state.repo_id, len(subsets))
    except Exception:
        pass
    print(f"Wrote {len(subsets)} subsets to {OUTPUT_FILE}")


# ---------- Public API ---------- #

def run(repo_id: str | None = None, codebase_path: str | Path | None = None) -> Path:
    """Pipeline step: group files into subsets; returns output path."""
    
    if repo_id is not None:
        app_state.repo_id = repo_id
    if codebase_path is not None:
        app_state.codebase_path = Path(codebase_path)

    main()
    return OUTPUT_FILE


if __name__ == "__main__":
    run()
