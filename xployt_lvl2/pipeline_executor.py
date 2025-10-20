import json
import os
from pathlib import Path
from typing import Any, List, Dict, Optional
from openai import OpenAI
from xployt_lvl2.config.settings import settings as _settings
from xployt_lvl2.config.state import app_state
from xployt_lvl2.utils.state_utils import get_output_dir, get_subset_file, get_suggestions_file, get_pipelines_file

STORAGE_CFG = {
    "global_store_enabled": True,
    "log_level": "info",
    "include_file_hashes": True,
    "format": "json",
}

# Hardcoded schemas for different output types
SCHEMAS = {
    "extract_vulnerabilities": {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "code_snippet": {"type": "string"},
                "line": {"type": "integer"},
                "description": {"type": "string"},
                "vulnerability": {"type": "string"},
                "severity": {"type": "string", "enum": ["Low", "Medium", "High", "Critical"]},
                "confidence_level": {"type": "string", "enum": ["Low", "Medium", "High"]}
            },
            "required": ["file_path", "code_snippet", "line", "description", "vulnerability", "severity", "confidence_level"]
        }
    },
    "remediation_suggestions": {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "code_snippet": {"type": "string"},
                "line": {"type": "integer"},
                "description": {"type": "string"},
                "vulnerability": {"type": "string"},
                "severity": {"type": "string", "enum": ["Low", "Medium", "High", "Critical"]},
                "confidence_level": {"type": "string", "enum": ["Low", "Medium", "High"]},
                "remediation": {"type": "string"}
            },
            "required": ["file_path", "line", "description", "vulnerability", "severity", "confidence_level", "remediation"]
        }
    }
}


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


# def render_prompt(template: str, context: dict[str, Any]) -> str:
#     return template.format(**context)


def run_stage(client: OpenAI, stage: dict, context: dict[str, Any]) -> str:
    """Execute a single pipeline stage with the given context."""
    
    # Build user prompt
    prompt = stage["prompt_template"]
    
    # Add example to prompt if available
    if "example" in stage:
        prompt += f"\n\nResponse should follow this example format:\n{json.dumps(stage['example'], indent=2)}"
    
    # Inject previous output if requested
    if stage.get("inject_previous_output"):
        prev = context.get(stage.get("input_tag"), "")
        if prev:
            prompt += f"\n{prev}"
    
    # Inject file contents
    if "file_contents" in context:
        prompt += f"\n```\n{context['file_contents']}\n```"
    
    # Build system message based on schema requirements
    schema_name = stage.get("schema")
    if schema_name and schema_name in SCHEMAS:
        system_message = _build_schema_system_message(schema_name, stage)
    else:
        system_message = "You are a senior security auditor."
    
    # Prepare request parameters
    request_params = {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": system_message},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 420,
    }
    
    # Add JSON response format if schema is provided
    if schema_name and schema_name in SCHEMAS:
        request_params["response_format"] = {"type": "json_object"}
    
    response = client.chat.completions.create(**request_params)
    return response.choices[0].message.content.strip()


def _build_schema_system_message(schema_name: str, stage: dict) -> str:
    """Build a schema-specific system message for the LLM."""
    example_json = json.dumps(stage.get("example", []), indent=2)
    schema_json = json.dumps(SCHEMAS[schema_name], indent=2)
    
    if schema_name == "extract_vulnerabilities":
        return (
            f"You are a senior security auditor. Your task is to identify security vulnerabilities.\n\n"
            f"IMPORTANT: You MUST format your response as a JSON object with a 'vulnerabilities' key containing an array of vulnerability objects.\n"
            f"Be brief and concise in your descriptions.\n"
            f"At most give 5 vulnerabilities.\n"
            f"CRITICAL: Extract code snippets EXACTLY as they appear in the source code - do not modify, format, or truncate them.\n"
            f"Example format: {{ \"vulnerabilities\": [{example_json}] }}\n\n"
            f"Each vulnerability object MUST follow this schema:\n{schema_json}"
        )
    elif schema_name == "remediation_suggestions":
        return (
            f"You are a senior security auditor. Your task is to suggest remediations for identified vulnerabilities.\n\n"
            f"IMPORTANT: You MUST format your response as a JSON object with a 'vulnerabilities' key containing an array of vulnerability objects with remediation details.\n"
            f"Be brief and concise in your remediation suggestions.Return other details as is.\n"
            f"Example format: {{ \"vulnerabilities\": [{example_json}] }}\n\n"
            f"Each vulnerability object MUST follow this schema:\n{schema_json}"
        )
    else:
        # Generic schema message
        return (
            f"You are a senior security auditor. Respond with valid JSON that matches the following schema:\n"
            f"{schema_json}"
        )


def run_pipeline_on_subset(subset: dict, pipeline_def: dict, client: OpenAI) -> list:
    """Execute one pipeline on a subset and return detected vulnerabilities."""
    # Load code of all files for context (concatenate, may be large; in prod stream per file)
    code_concat = "\n\n".join([
        Path(f).read_text(encoding="utf-8", errors="ignore")
        for f in subset["file_paths"]
        if Path(f).is_file()
    ])[:_settings.token_limit_per_subset_files_for_pipeline_execution]  # truncate to reduce tokens

    ctx: dict[str, Any] = {"file_contents": code_concat}
    saved_files: List[str] = []
    vulnerabilities_and_remediations = []

    for stage in pipeline_def["stages"]:
        output = run_stage(client, stage, ctx)
        if stage.get("save_output"):
            tag = stage["output_tag"]
            ctx[tag] = output
            fname = f"{subset['subset_id']}_{pipeline_def['pipeline_id']}_{tag}.json"
            
            # Parse and save the output
            try:
                # Always try to parse as JSON first
                parsed_output = json.loads(output)
                
                # Collect vulnerabilities if this is a vulnerability detection stage
                if stage.get("schema") in ["remediation_suggestions", "extract_vulnerabilities"]:
                    if isinstance(parsed_output, dict) and "vulnerabilities" in parsed_output:
                        vulnerabilities_and_remediations.extend(parsed_output["vulnerabilities"])
                    elif isinstance(parsed_output, list):
                        print(f"Warning: LLM output for {fname} is missing 'vulnerabilities' wrapper field")
                        vulnerabilities_and_remediations.extend(parsed_output)
                    else:
                        print(f"Warning: Unable to extract vulnerabilities from {fname}, unexpected format")
                
                # Write the parsed JSON directly (no wrapper)
                with open(get_output_dir() / fname, 'w', encoding='utf-8') as f:
                    json.dump(parsed_output, f, indent=2, ensure_ascii=False)
                    
            except json.JSONDecodeError:
                # If parsing fails, write as plain text
                print(f"Warning: Could not parse JSON output for {fname}, saving as plain text")
                with open(get_output_dir() / fname, 'w', encoding='utf-8') as f:
                    json.dump({"raw_output": output}, f, indent=2, ensure_ascii=False)

            saved_files.append(str(fname))
            if STORAGE_CFG["log_level"] == "info":
                print(f"   ↳ saved {fname}")

    return vulnerabilities_and_remediations


def _execute_pipelines() -> list:
    client = OpenAI(api_key=_settings.openai_api_key)

    subsets = {s["subset_id"]: s for s in load_json(get_subset_file())}
    suggestions = load_json(get_suggestions_file())
    pipelines_index = {
        p["pipeline_id"]: p for p in load_json(get_pipelines_file())["pipelines"]
    }

    all_vulnerabilities_and_remediations = []
    for entry in suggestions:
        subset_id = entry["subset_id"]
        subset = subsets[subset_id]
        for pipeline_id in entry["suggested_pipelines"]:
            pipeline_def = pipelines_index[pipeline_id]
            print(f"▶ Running {pipeline_id} on {subset_id} ({len(subset['file_paths'])} files)")
            vulnerabilities_and_remediations = run_pipeline_on_subset(subset, pipeline_def, client)
            print("vulnerabilities: ", vulnerabilities_and_remediations)
            all_vulnerabilities_and_remediations.extend(vulnerabilities_and_remediations)

    print("all_vulnerabilities_and_remediations: ", all_vulnerabilities_and_remediations)
    return all_vulnerabilities_and_remediations


# ---------- Public API ---------- #


def run(repo_id: str | None = None, codebase_path: str | Path | None = None) -> list:
    """Execute LLM pipelines on each subset; returns both the vulnerabilities file path and the vulnerabilities list."""

    if repo_id is not None:
        app_state.repo_id = repo_id
    if codebase_path is not None:
        app_state.codebase_path = Path(codebase_path)
    # print (app_state.codebase_path)
    # print (app_state.repo_id)

    all_vulnerabilities_and_remediations = _execute_pipelines()
    
    # Write vulnerabilities to a dedicated file
    vulns_path = get_output_dir() / f"{app_state.repo_id}_vulnerabilities.json"
    with open(vulns_path, 'w', encoding='utf-8') as f:
        json.dump({"vulnerabilities": all_vulnerabilities_and_remediations}, f, indent=2, ensure_ascii=False)
    
    
    print(f"Found {len(all_vulnerabilities_and_remediations)} vulnerabilities, saved to {vulns_path}")
    
    # Return both the file path to vulnerabilities and the actual vulnerabilities list
    return all_vulnerabilities_and_remediations


if __name__ == "__main__":
    run()
