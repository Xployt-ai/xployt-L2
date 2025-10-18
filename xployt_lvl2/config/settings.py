from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
import yaml
import os
from dotenv import load_dotenv
_defaults = Path(__file__).with_name("defaults.yaml")
load_dotenv()

class Settings(BaseSettings):
    # Core settings
    repo_id: str | None = None
    codebase_path: Path = Path(".")
    output_root: Path = Path("output")
    
    # LLM settings
    llm_model: str = "gpt-4o"
    llm_model_for_subset_grouping: str = "gpt-4o"
    temperature: float = 0.1
    openai_api_key: str | None = os.getenv("OPENAI_API_KEY")
    
    # Processing limits
    metadata_max_files: int | None = None
    select_vul_files_limit: int | None = None
    file_limit_per_subset_when_selecting_pipelines: int | None = None

# load YAML defaults, then let env-vars win
_settings_dict = yaml.safe_load(_defaults.read_text())
settings = Settings(**_settings_dict)  # singleton

__all__ = ["settings"]