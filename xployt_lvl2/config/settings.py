from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
import yaml

_defaults = Path(__file__).with_name("defaults.yaml")

class Settings(BaseSettings):
    repo_id: str | None = None
    codebase_path: Path = Path(".")
    output_root: Path = Path("output")
    llm_model: str = "gpt-4o"
    temperature: float = 0.1

    # optional overrides (from .env or other sources)
    openai_api_key: str | None = None
    metadata_max_files: int | None = None
    select_vul_files_limit: int | None = None

    # allow .env overrides so existing workflows keep working
    model_config = SettingsConfigDict(env_file=".env", env_prefix="")

# load YAML defaults, then let env-vars win
_settings_dict = yaml.safe_load(_defaults.read_text())
settings = Settings(**_settings_dict)  # singleton

__all__ = ["settings"]