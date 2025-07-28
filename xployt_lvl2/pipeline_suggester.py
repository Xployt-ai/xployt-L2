import json
import os
from pathlib import Path
from typing import List

from openai import OpenAI
from utils.path_utils import data_dir as _data_dir
from xployt_lvl2.config.settings import settings as _settings

DATA_DIR = _data_dir()
SUBSETS_FILE = DATA_DIR / "file_subsets.json"
METADATA_FILE = DATA_DIR / "vuln_file_metadata.json"
OUTPUT_FILE = DATA_DIR / "subset_pipeline_suggestions.json"

CONFIG_DIR = Path("config")
PIPELINES_DEF = CONFIG_DIR / "pipelines.json"

# ---------------------------
# Utilities
# ---------------------------

def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def subset_summary(subset: dict, metadata: dict) -> str:
    """Return a compact human-readable summary of the subset for the LLM."""
    lines = []
    for fp in subset["file_paths"][:10]:  # cap at 10 to save tokens
        meta = metadata.get(fp, {})
        desc = meta.get("description", "")
        lang = meta.get("language", "")
        side = meta.get("side", "")
        lines.append(f"• {fp} [{side}/{lang}]: {desc}")
    if len(subset["file_paths"]) > 10:
        lines.append(f"… {len(subset['file_paths']) - 10} more files omitted for brevity …")
    return "\n".join(lines)


def ask_llm_for_pipelines(client: OpenAI, subset: dict, pipelines: List[dict], metadata: dict) -> List[str]:
    pipe_desc = "\n".join(
        f"- {p['pipeline_id']}: {p['description']} (targets {', '.join(p['target_vulnerabilities'])})" for p in pipelines
    )

    prompt = f"""You are a senior security auditor. Your task is to choose which analysis pipelines from the list below should be applied to a subset of code files. Return ONLY a JSON array of pipeline_id strings.

Available pipelines:
{pipe_desc}

Here is the code subset description:
{subset_summary(subset, metadata)}
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a senior security auditor."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        max_tokens=120,
    )
    content = response.choices[0].message.content.strip()
    # Attempt to parse JSON array
    try:
        parsed = json.loads(content)
        if isinstance(parsed, list):
            return [pid for pid in parsed if isinstance(pid, str)]
    except Exception:
        pass
    # Fallback: choose generic injection checker
    return ["pipeline_injection"]


# ---------- core implementation ---------- #

def _suggest_pipelines() -> None:
    client = OpenAI(api_key=_settings.openai_api_key)

    subsets = load_json(SUBSETS_FILE)
    pipelines = load_json(PIPELINES_DEF)["pipelines"]
    metadata = load_json(METADATA_FILE)

    results = []
    for subset in subsets:
        suggested = ask_llm_for_pipelines(client, subset, pipelines, metadata)
        results.append({
            "subset_id": subset["subset_id"],
            "suggested_pipelines": suggested,
        })
        print(f"✅ {subset['subset_id']}: {', '.join(suggested)}")

    OUTPUT_FILE.write_text(json.dumps(results, indent=2))
    print(f"\n🎉 Suggestions written to {OUTPUT_FILE}")


# ---------- Public API ---------- #

def run(repo_id: str | None = None, codebase_path: str | Path | None = None) -> Path:
    """Pipeline step: suggest pipelines for each subset and write JSON."""
    _suggest_pipelines()
    return OUTPUT_FILE


if __name__ == "__main__":
    run()
