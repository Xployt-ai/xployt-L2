#!/usr/bin/env python
"""
Simple test script to print all settings variables.
"""

import sys
from pathlib import Path

# Add parent directory to path so we can import the package
sys.path.insert(0, str(Path(__file__).parent.parent))

from xployt_lvl2.config.settings import settings

def main():
    """Print all settings variables."""
    print("=" * 50)
    print("SETTINGS VARIABLES")
    print("=" * 50)
    
    # Print core settings
    print("\nCore Settings:")
    print(f"  repo_id: {settings.repo_id}")
    print(f"  codebase_path: {settings.codebase_path}")
    print(f"  output_root: {settings.output_root}")
    
    # Print LLM settings
    print("\nLLM Settings:")
    print(f"  llm_model: {settings.llm_model}")
    print(f"  temperature: {settings.temperature}")
    print(f"  openai_api_key: {settings.openai_api_key}")
    
    # Print processing limits
    print("\nProcessing Limits:")
    print(f"  metadata_max_files: {settings.metadata_max_files}")
    print(f"  select_vul_files_limit: {settings.select_vul_files_limit}")
    
    print("\n" + "=" * 50)

if __name__ == "__main__":
    main()
