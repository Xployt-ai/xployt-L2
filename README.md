# Xployt-L2 – Helper Scripts for Vulnerability Triage

These utilities prepare smaller, model-friendly chunks of a MERN-stack codebase for LLM-based vulnerability scanning.

---
## Directory layout

```
/data
  file_tree.json              # raw file/folder structure of the target repo
  vuln_files_selection.json   # OpenAI-picked folders + standalone files
  vuln_file_metadata.json     # per-file metadata & summaries (backend + frontend)
  file_subsets.json           # GPT-4-clustered file subsets
  subset_pipeline_suggestions.json # suggested pipelines per subset
  pipeline_outputs/           # LLM outputs for each pipeline stage

get_file_struct.py            # quick console tree printer (no JSON)
get_file_struct_json.py       # writes /data/file_tree.json
select_vuln_files.py          # asks GPT-4 for which parts look security-relevant
generate_metadata.py          # builds rich metadata + summaries for each path
group_subsets.py              # clusters files into logical subsets
pipeline_suggester.py         # suggests pipelines per subset
pipeline_executor.py          # executes pipelines on each subset
main.py                       # FastAPI server for pipeline automation
```

---
## Required environment variables (.env)

```
OPENAI_API_KEY=<your key>
CODEBASE_PATH=<absolute path to the repo you want to analyse>
# optional – limit number of files processed by generate_metadata.py
METADATA_MAX_FILES=25
```

Create a `.env` file in the project root or export them in your shell.

---
## Installing dependencies

This repo uses Poetry:

```bash
poetry install
```

---
## Usage – step by step

1. **Scan filesystem and build JSON tree**

   ```bash
   poetry run python get_file_struct_json.py
   # -> writes data/file_tree.json
   ```

2. **Let GPT-4 decide which folders/files deserve security attention**

   ```bash
   poetry run python select_vuln_files.py
   # -> writes data/vuln_files_selection.json
   ```

3. **Generate per-file metadata & natural-language summaries**

   ```bash
   # full run
   poetry run python generate_metadata.py

   # or limit to N files for a cheap dry-run
   METADATA_MAX_FILES=10 poetry run python generate_metadata.py

   # or analyse a different repo root
   poetry run python generate_metadata.py --base /some/other/path
   ```

4. **Group files into functional subsets**

   ```bash
   poetry run python group_subsets.py
   # -> writes data/file_subsets.json
   ```

5. **Suggest analysis pipelines for each subset**

   ```bash
   poetry run python pipeline_suggester.py
   # -> writes data/subset_pipeline_suggestions.json
   ```

6. **Execute pipelines on each subset**

   ```bash
   poetry run python pipeline_executor.py
   # -> writes results under data/pipeline_outputs/
   ```

---
## Script details

| Script | What it does | Key outputs |
| ------ | ------------ | ----------- |
| `get_file_struct.py` | Pretty-prints a depth-limited directory tree to stdout. Handy for a quick visual inspection. | – |
| `get_file_struct_json.py` | Recursively walks the repo (honours `EXCLUDE_DIRS`) and dumps a JSON object representing folders & files. Uses `CODEBASE_PATH` if set. | `data/file_tree.json` |
| `select_vuln_files.py` | Sends the JSON tree to GPT-4 with a prompt asking for potentially vulnerable areas. Stores the returned JSON lists. | `data/vuln_files_selection.json` |
| `generate_metadata.py` | Reads the selection, computes language/LOC/imports per file, calls GPT-4 for a 2-3 sentence summary (cached via SHA-1), and writes a consolidated metadata file. | `data/vuln_file_metadata.json` |
| `group_subsets.py` | Uses GPT-4 to cluster files into logical subsets based on functional connections (data flow, MVC, shared state). | `data/file_subsets.json` |
| `pipeline_suggester.py` | For each subset, asks GPT-4 which vulnerability analysis pipelines should run and stores suggestions. | `data/subset_pipeline_suggestions.json` |
| `pipeline_executor.py` | Executes the suggested pipelines per subset and persists LLM outputs for each pipeline stage. | `data/pipeline_outputs/` |

---
## Updating / re-running

• If your codebase changes, re-run the scripts in order. `generate_metadata.py` only re-summarises files whose SHA-1 changed, saving tokens.
• Delete files in `/data` to force a full rebuild.

---
## Example workflow (one-liner)

```bash
# Assume .env has OPENAI_API_KEY and CODEBASE_PATH already
poetry run python get_file_struct_json.py && \
poetry run python select_vuln_files.py && \
poetry run python generate_metadata.py && \
poetry run python group_subsets.py && \
poetry run python pipeline_suggester.py && \
poetry run python pipeline_executor.py
```

You now have everything needed to batch code & summaries into LLM-sized chunks for vulnerability analysis.

---
## REST API – Pipeline Runner

The FastAPI server (see `main.py`) exposes a single endpoint to automate the entire workflow from your CI/CD pipeline.

### `POST /run-pipeline`

Runs the standard six-step pipeline described above.

Request body (JSON):

```json
{
  "id": "v1.2.3",          // Arbitrary version or run identifier – stored as VERSION in .env
  "path": "/abs/path/to/repo"  // Path to the codebase to analyse – stored as CODEBASE_PATH in .env
}
```

Behavior:
1. Updates/creates `.env` with `VERSION` and `CODEBASE_PATH`.
2. Executes scripts in this order, aborting on first failure:
   - `get_file_struct_json.py`
   - `select_vuln_files.py`
   - `generate_metadata.py`
   - `group_subsets.py`
   - `pipeline_suggester.py`
   - `pipeline_executor.py`
3. Returns JSON containing the stdout of the last executed script.

Successful response example:

```json
{
  "success": true,
  "output": "✅ Suggestions written to 2025-07-20_data/pipeline_outputs/..."
}
```

If a script fails, the API returns HTTP 500 with details.
