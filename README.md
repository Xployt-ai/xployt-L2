# Xployt-L2 – Helper Scripts for Vulnerability Triage

These utilities prepare smaller, model-friendly chunks of a MERN-stack codebase for LLM-based vulnerability scanning.

---
## Directory layout

```
/data
  file_tree.json              # raw file/folder structure of the target repo
  vuln_files_selection.json   # OpenAI-picked folders + standalone files
  vuln_file_metadata.json     # per-file metadata & summaries (backend + frontend)

get_file_struct.py            # quick console tree printer (no JSON)
get_file_struct_json.py       # writes /data/file_tree.json
select_vuln_files.py          # asks GPT-4 for which parts look security-relevant
generate_metadata.py          # builds rich metadata + summaries for each path
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

---
## Script details

| Script | What it does | Key outputs |
| ------ | ------------ | ----------- |
| `get_file_struct.py` | Pretty-prints a depth-limited directory tree to stdout. Handy for a quick visual inspection. | – |
| `get_file_struct_json.py` | Recursively walks the repo (honours `EXCLUDE_DIRS`) and dumps a JSON object representing folders & files. Uses `CODEBASE_PATH` if set. | `data/file_tree.json` |
| `select_vuln_files.py` | Sends the JSON tree to GPT-4 with a prompt asking for potentially vulnerable areas. Stores the returned JSON lists. | `data/vuln_files_selection.json` |
| `generate_metadata.py` | Reads the selection, computes language/LOC/imports per file, calls GPT-4 for a 2-3 sentence summary (cached via SHA-1), and writes a consolidated metadata file. | `data/vuln_file_metadata.json` |

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
poetry run python generate_metadata.py
```

You now have everything needed to batch code & summaries into LLM-sized chunks for vulnerability analysis.
