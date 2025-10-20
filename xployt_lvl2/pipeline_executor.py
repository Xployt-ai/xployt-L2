import json
import os
import time
from pathlib import Path
from typing import Any, List, Dict, Optional
from difflib import SequenceMatcher
from xployt_lvl2.config.settings import settings as _settings
from xployt_lvl2.config.state import app_state
from xployt_lvl2.utils.state_utils import get_output_dir, get_subset_file, get_suggestions_file, get_pipelines_file
from xployt_lvl2.utils.langsmith_wrapper import traced_chat_completion_raw, traced_gpt5_completion_raw

# Rate limiting: delay between API calls (in seconds)
RATE_LIMIT_DELAY = 5.0  # Adjust this value to control request rate

# Hardcoded schemas for different output types
SCHEMAS = {
    "vulnerabilities_with_remediations": {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "code_snippet": {"type": "string"},
                "description": {"type": "string"},
                "vulnerability": {"type": "string"},
                "severity": {"type": "string", "enum": ["Low", "Medium", "High", "Critical"]},
                "confidence_level": {"type": "string", "enum": ["Low", "Medium", "High"]},
                "remediation": {"type": "string"}
            },
            "required": ["file_path", "description", "vulnerability", "severity", "confidence_level", "remediation"]
        }
    }
}


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def find_line_number_fuzzy(file_path: str, code_snippet: str, threshold: float = 0.6) -> Optional[List[int]]:
    """Find the line number(s) of a code snippet in a file using fuzzy matching.
    
    Args:
        file_path: Path to the file to search in
        code_snippet: Code snippet to find
        threshold: Minimum similarity ratio (0-1) to consider a match
    
    Returns:
        List of line numbers (1-indexed) where the snippet was found.
        For single-line matches: [line_num]
        For multi-line matches: [start, start+1, ..., end]
        Returns None if not found
    """
    try:
        file_path_obj = Path(file_path)
        if not file_path_obj.exists() or not file_path_obj.is_file():
            return None
        
        with file_path_obj.open("r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        
        # Normalize the snippet for comparison (collapse all whitespace to single spaces)
        snippet_normalized = " ".join(code_snippet.split())
        
        best_match_lines = None
        best_match_ratio = 0.0
        best_start_line = 0
        best_end_line = 0
        
        # Use a sliding window approach with variable window sizes
        # This handles cases where LLM formatting differs from actual code
        # (e.g., 1 LLM line → multiple file lines, or vice versa)
        
        # Try different window sizes from 1 to min(20, total lines)
        max_window_size = min(7, len(lines))
        
        for window_size in range(1, max_window_size + 1):
            for start_idx in range(len(lines) - window_size + 1):
                # Get window of lines and normalize
                window = "".join(lines[start_idx:start_idx + window_size])
                window_normalized = " ".join(window.split())
                
                # Calculate similarity ratio
                ratio = SequenceMatcher(None, snippet_normalized, window_normalized).ratio()
                
                if ratio > best_match_ratio:
                    best_match_ratio = ratio
                    best_start_line = start_idx + 1  # 1-indexed
                    best_end_line = start_idx + window_size
        
        # Return match if it meets the threshold
        if best_match_ratio >= threshold:
            if best_start_line == best_end_line:
                best_match_lines = [best_start_line]
            else:
                best_match_lines = list(range(best_start_line, best_end_line + 1))
        
        return best_match_lines
    
    except Exception as e:
        print(f"Error finding line number in {file_path}: {e}")
        return None


def run_stage(stage: dict, context: dict[str, Any]) -> str:
    """Execute a single pipeline stage with the given context."""
    
    # Build system message: prompt_template -> schema -> example
    system_message = "You are a senior security auditor.\n\n"
    system_message += stage["prompt_template"]
    
    # Add schema (always present)
    schema_json = json.dumps(SCHEMAS["vulnerabilities_with_remediations"], indent=2)
    system_message += f"\n\nYou MUST format your response as a JSON object with a 'vulnerabilities' key containing an array of vulnerability objects."
    system_message += f"\nEach vulnerability object MUST follow this schema:\n{schema_json}"
    
    # Add example (always present)
    example_json = json.dumps(stage["example"], indent=2)
    system_message += f"\n\nBelow is an example response. Use it as a reference only:"
    system_message += f"\n\n{example_json}"
    # Build user message: only file contents
    user_message = f"```\n{context['file_contents']}\n```"
    
    # Build operation name for LangSmith tracing
    operation_name = f"pipeline-stage-{stage['id']}"
    
    # Use appropriate wrapper based on model type
    model = _settings.llm_model_for_pipeline_execution
    
    if model in ["gpt-5", "gpt-5-mini"]:
        # Use GPT-5 specific function (no temperature, uses max_completion_tokens)
        response = traced_gpt5_completion_raw(
            messages=[
                {"role": "system", "content": system_message},
                {"role": "user", "content": user_message},
            ],
            model=model,
            max_completion_tokens=720,
            # reasoning_effort="low",
            response_format={"type": "json_object"},
            operation_name=operation_name
        )
    else:
        # Use standard GPT-4 function
        response = traced_chat_completion_raw(
            messages=[
                {"role": "system", "content": system_message},
                {"role": "user", "content": user_message},
            ],
            model=model,
            max_tokens=720,
            response_format={"type": "json_object"},
            operation_name=operation_name
        )
    
    return response.choices[0].message.content.strip()


def run_pipeline_on_subset(subset: dict, pipeline_def: dict) -> list:
    """Execute one pipeline on a subset and return detected vulnerabilities."""
    # Load code of all files for context with clear file separators
    file_parts = []
    for f in subset["file_paths"]:
        file_path = Path(f)
        if file_path.is_file():
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                # Add clear separator with filename
                file_part = f"\n{'='*5}\n"
                file_part += f"FILE: {f}\n"
                file_part += f"{'='*5}\n"
                file_part += content
                file_part += f"\n{'='*5}\n"
                file_part += f"END OF FILE: {f}\n"
                file_part += f"{'='*5}\n"
                file_parts.append(file_part)
            except Exception as e:
                print(f"Warning: Could not read file {f}: {e}")
    
    code_concat = "\n".join(file_parts)[:_settings.token_limit_per_subset_files_for_pipeline_execution]  # truncate to reduce tokens

    ctx: dict[str, Any] = {"file_contents": code_concat}
    vulnerabilities_and_remediations = []

    # Since we now have single-stage pipelines, process the only stage
    stage = pipeline_def["stages"][0]  # Get the first (and only) stage
    output = run_stage(stage, ctx)
    
    # Parse and collect vulnerabilities
    try:
        parsed_output = json.loads(output)
        
        # Extract vulnerabilities with remediations
        if isinstance(parsed_output, dict) and "vulnerabilities" in parsed_output:
            vulnerabilities_and_remediations = parsed_output["vulnerabilities"]
        elif isinstance(parsed_output, list):
            print(f"Warning: LLM output is missing 'vulnerabilities' wrapper field")
            vulnerabilities_and_remediations = parsed_output
        else:
            print(f"Warning: Unable to extract vulnerabilities, unexpected format")
        
        # Save the output
        if stage.get("save_output"):
            tag = stage["output_tag"]
            fname = f"{subset['subset_id']}_{pipeline_def['pipeline_id']}_{tag}.json"
            with open(get_output_dir() / fname, 'w', encoding='utf-8') as f:
                json.dump(parsed_output, f, indent=2, ensure_ascii=False)
                print(f"   ↓ saved {fname}")
                
    except json.JSONDecodeError:
        print(f"Warning: Could not parse JSON output, saving as plain text")
        if stage.get("save_output"):
            tag = stage["output_tag"]
            fname = f"{subset['subset_id']}_{pipeline_def['pipeline_id']}_{tag}.json"
            with open(get_output_dir() / fname, 'w', encoding='utf-8') as f:
                json.dump({"raw_output": output}, f, indent=2, ensure_ascii=False)
                print(f"   ↓ saved {fname}")
    
    # After all stages complete, find actual line numbers using fuzzy matching
    # Only do this if we have vulnerabilities with remediations (final stage)
    if vulnerabilities_and_remediations:
        print("\n➤ Finding actual line numbers using fuzzy matching...")
        for vuln in vulnerabilities_and_remediations:
            if "code_snippet" in vuln and "file_path" in vuln:
                code_snippet = vuln["code_snippet"]
                file_path = vuln["file_path"]
                
                # Find line number(s) using fuzzy matching
                line_nums = find_line_number_fuzzy(file_path, code_snippet)
                
                if line_nums is not None:
                    vuln["line"] = line_nums
                    if len(line_nums) == 1:
                        print(f"  ✓ Found line {line_nums[0]} for vulnerability in {file_path}")
                    else:
                        print(f"  ✓ Found lines {line_nums[0]}-{line_nums[-1]} for vulnerability in {file_path}")
                else:
                    # Set to empty list to mark for removal
                    vuln["line"] = []
                    print(f"  ⚠ Could not find exact line for vulnerability in {file_path}")
    
    # Filter out vulnerabilities where line numbers couldn't be found
    original_count = len(vulnerabilities_and_remediations)
    vulnerabilities_and_remediations = [
        vuln for vuln in vulnerabilities_and_remediations 
        if vuln.get("line") and len(vuln.get("line", [])) > 0
    ]
    removed_count = original_count - len(vulnerabilities_and_remediations)
    if removed_count > 0:
        print(f"\n  🗑️  Removed {removed_count} vulnerability(ies) without valid line numbers")
    
    # Convert absolute file path to relative filepath with forward slashes
    for vuln in vulnerabilities_and_remediations:
        if "file_path" in vuln:
            vuln["file_path"] = Path(vuln["file_path"]).relative_to(app_state.codebase_path).as_posix()
    
    return vulnerabilities_and_remediations


def _execute_pipelines() -> list:
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
            vulnerabilities_and_remediations = run_pipeline_on_subset(subset, pipeline_def)
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
