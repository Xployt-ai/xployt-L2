import json
import os
from pathlib import Path
from typing import Any
from dotenv import load_dotenv
from openai import OpenAI

DATA_DIR = Path("data")
SUBSET_FILE = DATA_DIR / "file_subsets.json"
SUGGESTIONS_FILE = DATA_DIR / "subset_pipeline_suggestions.json"
PIPELINES_FILE = DATA_DIR / "pipelines.json"
OUTPUT_DIR = DATA_DIR / "pipeline_outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

STORAGE_CFG = {
    "global_store_enabled": True,
    "log_level": "info",
    "include_file_hashes": True,
    "format": "json",
}


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def render_prompt(template: str, context: dict[str, Any]) -> str:
    return template.format(**context)


def run_stage(client: OpenAI, stage: dict, context: dict[str, Any]) -> str:
    prompt = stage["prompt_template"]
    if stage.get("inject_previous_output"):
        # Replace simple placeholder {previous_output}
        prev = context.get(stage.get("input_tag"))
        prompt = prompt + "\n" + prev
    # For now also inject filenames
    if "file_contents" in context:
        prompt = prompt + "\n```\n" + context["file_contents"] + "\n```"

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a senior security auditor."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        max_tokens=512,
    )
    return response.choices[0].message.content.strip()


def run_pipeline_on_subset(subset: dict, pipeline_def: dict, client: OpenAI):
    # Load code of all files for context (concatenate, may be large; in prod stream per file)
    code_concat = "\n\n".join([
        Path(f).read_text(encoding="utf-8", errors="ignore")
        for f in subset["file_paths"]
        if Path(f).is_file()
    ])[:8000]  # truncate to reduce tokens

    ctx: dict[str, Any] = {"file_contents": code_concat}

    for stage in pipeline_def["stages"]:
        output = run_stage(client, stage, ctx)
        if stage.get("save_output"):
            tag = stage["output_tag"]
            ctx[tag] = output
            fname = f"{subset['subset_id']}_{pipeline_def['pipeline_id']}_{tag}.json"
            (OUTPUT_DIR / fname).write_text(json.dumps({"content": output}, indent=2))
            if STORAGE_CFG["log_level"] == "info":
                print(f"   ↳ saved {fname}")



def main():
    load_dotenv()
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    subsets = {s["subset_id"]: s for s in load_json(SUBSET_FILE)}
    suggestions = load_json(SUGGESTIONS_FILE)
    pipelines_index = {
        p["pipeline_id"]: p for p in load_json(PIPELINES_FILE)["pipelines"]
    }

    for entry in suggestions:
        subset_id = entry["subset_id"]
        subset = subsets[subset_id]
        for pipeline_id in entry["suggested_pipelines"]:
            pipeline_def = pipelines_index[pipeline_id]
            print(f"▶ Running {pipeline_id} on {subset_id} ({len(subset['file_paths'])} files)")
            run_pipeline_on_subset(subset, pipeline_def, client)


if __name__ == "__main__":
    main()
