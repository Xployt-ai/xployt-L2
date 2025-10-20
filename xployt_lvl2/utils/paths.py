from __future__ import annotations
from pathlib import Path
import re

# Detect Windows drive (e.g., C:/ or C:\)
_DRIVE_RE = re.compile(r"^[A-Za-z]:[/\\]")


def normalize_rel(p: str | Path | None) -> str:
    """Normalize a user/JSON-provided path to a POSIX-style relative path.
    - Converts backslashes to forward slashes
    - Removes drive letters and leading separators
    - Collapses duplicate separators
    """
    if p is None:
        return ""
    s = str(p).replace("\\", "/")
    s = _DRIVE_RE.sub("", s).lstrip("/")
    while "//" in s:
        s = s.replace("//", "/")
    return s


def split_rel(p: str | Path | None) -> list[str]:
    s = normalize_rel(p)
    return [part for part in s.split("/") if part and part != "."]


def safe_join(base: str | Path, rel: str | Path | None) -> Path:
    """Join base with a normalized relative path in a cross-platform safe way."""
    return Path(base).joinpath(*split_rel(rel))


def to_posix(p: str | Path) -> str:
    return str(p).replace("\\", "/")


def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

