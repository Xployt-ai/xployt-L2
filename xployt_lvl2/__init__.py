"""Xployt-lvl2 top-level package.

Exposes sub-packages and provides a temporary backward-compatibility
shim so legacy scripts that still import ``utils.path_utils`` continue
working while we migrate code into the package.
"""

from importlib import import_module as _import_module
import sys as _sys

# ---------------------------------------------------------------------------
# Backward-compatibility bridge
# ---------------------------------------------------------------------------
#   Old code frequently does ``from utils.path_utils import data_dir``.
#   We map that dotted name to the new package location so those imports
#   resolve without modification.  Once all scripts are migrated, this
#   shim can be removed.
# ---------------------------------------------------------------------------

_sys.modules.setdefault("utils.path_utils", _import_module("xployt_lvl2.utils.path_utils"))

# Expose this package under a lowercase alias so internal imports using
# ``xployt_lvl2`` (lowercase "lvl2") resolve correctly regardless of the
# actual directory casing on disk.
_sys.modules.setdefault("xployt_lvl2", _sys.modules[__name__])

# Re-export common namespaces for convenience
from types import ModuleType as _ModuleType

utils: _ModuleType = _import_module("xployt_lvl2.utils")
config: _ModuleType = _import_module("xployt_lvl2.config")

__all__ = [
    "utils",
    "config",
]