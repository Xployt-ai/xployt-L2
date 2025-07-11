import json
from pathlib import Path
from collections import defaultdict, deque
import os
from dotenv import load_dotenv
from openai import OpenAI

DATA_DIR = Path("data")
METADATA_FILE = DATA_DIR / "vuln_file_metadata.json"
OUTPUT_FILE = DATA_DIR / "file_subsets.json"

# Max files to include in LLM prompt for token control
MAX_FILES_IN_PROMPT = 120

def load_metadata() -> dict[str, dict]:
    if not METADATA_FILE.exists():
        raise FileNotFoundError(
            f"{METADATA_FILE} missing - run generate_metadata.py first")
    with METADATA_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)


def build_import_graph(meta: dict[str, dict]) -> dict[str, set[str]]:
    """Return adjacency list keyed by file path (str)."""
    graph: dict[str, set[str]] = defaultdict(set)
    for file_path, info in meta.items():
        if info.get("kind") != "file":
            continue
        for imp in info.get("imports", []):
            # Very naive resolution: if import path maps exactly to another file's
            # stem, add edge. For JS imports we also try common extension-less paths.
            for other_path in meta:
                if other_path == file_path:
                    continue
                if other_path.endswith(imp) or Path(other_path).stem == Path(imp).name:
                    graph[file_path].add(other_path)
                    graph[other_path].add(file_path)
    return graph


def find_connected_components(graph: dict[str, set[str]]):
    seen = set()
    for node in graph:
        if node in seen:
            continue
        comp = []
        dq = deque([node])
        seen.add(node)
        while dq:
            cur = dq.popleft()
            comp.append(cur)
            for nbr in graph[cur]:
                if nbr not in seen:
                    seen.add(nbr)
                    dq.append(nbr)
        yield comp


def heuristic_reason(files: list[str]) -> str:
    """Return human-readable reason for grouping."""
    # If all share a parent folder name, mention it
    parents = {Path(f).parts[-2] if len(Path(f).parts) >= 2 else "" for f in files}
    if len(parents) == 1:
        parent = next(iter(parents))
        return f"Files under common directory '{parent}' share imports"
    return "Interconnected via import statements"


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
        lines.append(f"- {path} [{side}/{lang}]: {summary}")
    if len(meta) > MAX_FILES_IN_PROMPT:
        lines.append(f"… {len(meta) - MAX_FILES_IN_PROMPT} more files omitted for brevity …")

    instructions = (
        "You are a senior full-stack architect specialising in security reviews of MERN projects. "
        "Group the following files into logical subsets based on data-flow, shared models, MVC relationships, shared state/props, or token/session usage. "
        "Return ONLY a JSON array where each element has keys 'subset_id', 'file_paths' (array of strings), and 'reason' (string explaining why those files belong together). "
        "Start subset_id numbering at 'subset-001'."
    )

    return instructions + "\n\nFiles:\n" + "\n".join(lines)


def ask_llm_for_grouping(meta: dict[str, dict]) -> list[dict] | None:
    """Call OpenAI to propose subsets. Returns list on success, else None."""
    load_dotenv()
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None

    client = OpenAI(api_key=api_key)
    prompt = build_llm_prompt(meta)

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a senior security auditor."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=700,
        )
        content = response.choices[0].message.content.strip()
        subsets = json.loads(content)
        if isinstance(subsets, list):
            return subsets
    except Exception:
        # Parsing or API error
        return None

    return None


def main():
    meta = load_metadata()

    # 1️⃣ Try LLM-powered grouping first
    subsets = ask_llm_for_grouping(meta) or []

    # 2️⃣ Fallback to heuristic graph if LLM failed or returned empty
    if not subsets:
        print("⚠️  Falling back to heuristic grouping (LLM unavailable or invalid output)…")
        graph = build_import_graph(meta)
        for idx, comp in enumerate(find_connected_components(graph), start=1):
            subset_id = f"subset-{idx:03d}"
            reason = heuristic_reason(comp)
            subsets.append({
                "subset_id": subset_id,
                "file_paths": comp,
                "reason": reason,
            })

        # Include unconnected files as individual subsets
        all_files_with_kind = [p for p, i in meta.items() if i.get("kind") == "file"]
        remaining = set(all_files_with_kind) - {p for s in subsets for p in s["file_paths"]}
        for idx, file_path in enumerate(sorted(remaining), start=len(subsets) + 1):
            subsets.append({
                "subset_id": f"subset-{idx:03d}",
                "file_paths": [file_path],
                "reason": "No connectivity – treated as standalone",
            })

    OUTPUT_FILE.write_text(json.dumps(subsets, indent=2))
    print(f"✅ Wrote {len(subsets)} subsets to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
