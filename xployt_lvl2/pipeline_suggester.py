import json
import os
from pathlib import Path
from typing import List

from xployt_lvl2.config.settings import settings as _settings
from xployt_lvl2.utils.state_utils import get_data_dir, get_subset_file, get_vuln_files_metadata_file, get_suggestions_file
from xployt_lvl2.utils.langsmith_wrapper import traced_chat_completion

CONFIG_DIR = Path(__file__).resolve().parent / "config"
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
    for fp in subset["file_paths"][:_settings.file_limit_per_subset_when_selecting_pipelines]:  # cap at 10 to save tokens
        meta = metadata.get(fp, {})
        desc = meta.get("description", "")
        lang = meta.get("language", "")
        side = meta.get("side", "")
        lines.append(f"• {fp} [{side}/{lang}]: {desc}")
    if len(subset["file_paths"]) > _settings.file_limit_per_subset_when_selecting_pipelines:
        lines.append(f"… {len(subset['file_paths']) - _settings.file_limit_per_subset_when_selecting_pipelines} more files omitted for brevity …")
    return "\n".join(lines)


def ask_llm_for_pipelines(subset: dict, pipelines: List[dict], metadata: dict) -> List[str]:
    pipe_desc = "\n".join(
        f"- {p['pipeline_id']}: {p['description']} (targets {', '.join(p['target_vulnerabilities'])})" for p in pipelines
    )

    prompt = f"""You are a senior security auditor. Your task is to choose which analysis pipelines from the list below should be applied to a subset of code files. Return ONLY a JSON array of pipeline_id strings.

Available pipelines:
{pipe_desc}

Here is the code subset description:
{subset_summary(subset, metadata)}
"""

    # Use traced utility function - automatically logs to LangSmith
    content = traced_chat_completion(
        messages=[
            {"role": "system", "content": "You are a senior security auditor."},
            {"role": "user", "content": prompt},
        ],
        model=_settings.llm_model_for_pipeline_suggestion,
        temperature=0.2,
        max_tokens=120,
        operation_name="suggest-pipelines"
    ).strip()
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
    subsets = load_json(get_subset_file())
    pipelines = load_json(PIPELINES_DEF)["pipelines"]
    metadata = load_json(get_vuln_files_metadata_file())

    results = []
    for subset in subsets:
        suggested = ask_llm_for_pipelines(subset, pipelines, metadata)
        results.append({
            "subset_id": subset["subset_id"],
            "suggested_pipelines": suggested,
        })
        print(f"✅ {subset['subset_id']}: {', '.join(suggested)}")

    output_file = get_suggestions_file()
    output_file.write_text(json.dumps(results, indent=2))
    print(f"\n🎉 Suggestions written to {output_file}")


# ---------- Public API ---------- #

def run(repo_id: str | None = None, codebase_path: str | Path | None = None) -> Path:
    """Pipeline step: suggest pipelines for each subset and write JSON."""
    _suggest_pipelines()
    return get_suggestions_file()


if __name__ == "__main__":
    run()
