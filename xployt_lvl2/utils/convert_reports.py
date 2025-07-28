#!/usr/bin/env python
import json
import pathlib
import os
from utils.path_utils import data_dir as _data_dir
import argparse

repo_id = os.getenv("REPO_ID")
DATA_DIR = _data_dir()

DEFAULT_SRC = pathlib.Path("v2_data/pipeline_outputs")

def convert(src: pathlib.Path, out: pathlib.Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    count = 0
    for f in src.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            content = data.get("content")
            if not isinstance(content, str):
                continue  # skip files without expected key
            md_path = out / f.with_suffix(".md").name
            md_path.write_text(content, encoding="utf-8")
            print("✓", md_path.relative_to(out.parent))
            count += 1
        except Exception as exc:
            print("⚠️  Skipped", f.name, "-", exc)
    print(f"\n✔ Converted {count} report(s) → {out}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert JSON pipeline reports into Markdown files.")
    parser.add_argument("--src", type=pathlib.Path, default=DEFAULT_SRC, help="Directory containing JSON reports")
    parser.add_argument("--out", type=pathlib.Path, default=None, help="Output directory for .md files (defaults to <src>/readable)")
    args = parser.parse_args()

    src_dir = args.src
    out_dir = args.out or (src_dir / "readable")
    convert(src_dir, out_dir)