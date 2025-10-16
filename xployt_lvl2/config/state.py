from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# ---- Application (run-scoped) state ---- #

@dataclass
class AppState:
    repo_id: Optional[str] = None
    codebase_path: Path = Path(".")

# Singleton instance mutated by the app
app_state = AppState()


# ---- Shared progress state (process-local cache) ---- #

@dataclass
class ProgressState:
    metadata_files: int | None = None
    subset_count: int | None = None

# Cache keyed by repo_id (so concurrent repos can be tracked independently)
_STATE_CACHE: dict[str, ProgressState] = {}


def _key(repo_id: Optional[str]) -> str:
    return repo_id or app_state.repo_id


def get_progress_state(repo_id: Optional[str] = None) -> ProgressState:
    key = _key(repo_id)
    state = _STATE_CACHE.get(key)
    if state is None:
        state = ProgressState()
        _STATE_CACHE[key] = state
    return state


def reset_progress_state(repo_id: Optional[str] = None) -> None:
    _STATE_CACHE[_key(repo_id)] = ProgressState()


def set_metadata_files_count(repo_id: Optional[str], n: int) -> int:
    ps = get_progress_state(repo_id)
    ps.metadata_files = n
    return n

def get_metadata_files_count(repo_id: Optional[str]) -> int | None:
    ps = get_progress_state(repo_id)
    return ps.metadata_files

def set_subset_count(repo_id: Optional[str], n: int) -> int:
    ps = get_progress_state(repo_id)
    ps.subset_count = n
    return n

def get_subset_count(repo_id: Optional[str]) -> int | None:
    ps = get_progress_state(repo_id)
    return ps.subset_count

__all__ = [
    "app_state",
    "AppState",
    "ProgressState",
    "get_progress_state",
    "reset_progress_state",
    "set_metadata_files_count",
    "get_metadata_files_count",
    "set_subset_count",
    "get_subset_count",
]
