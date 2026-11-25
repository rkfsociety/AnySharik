"""AnySharik OrcaSlicer plugin package."""

from __future__ import annotations

import os
import shutil
import stat
import sys
import time
from pathlib import Path


def _win_long_path(path: Path) -> str:
    raw = str(path.resolve())
    if sys.platform == "win32" and not raw.startswith("\\\\?\\"):
        if raw.startswith("\\\\"):
            return "\\\\?\\UNC\\" + raw[2:]
        return "\\\\?\\" + raw
    return raw


def _handle_remove_error(func, target, _exc):
    try:
        os.chmod(target, stat.S_IWRITE)
        func(target)
    except OSError:
        pass


def _remove_tree(path: Path, retries: int = 5, delay: float = 0.15) -> None:
    """Remove a directory tree reliably on Windows, including MAX_PATH and read-only files."""
    if not path.exists():
        return
    kwargs = (
        {"onexc": _handle_remove_error}
        if sys.version_info >= (3, 12)
        else {"onerror": lambda func, target, exc_info: _handle_remove_error(func, target, exc_info)}
    )
    target = _win_long_path(path)
    for attempt in range(max(1, retries)):
        try:
            shutil.rmtree(target, **kwargs)
        except OSError:
            pass
        if not path.exists():
            return
        if attempt + 1 < retries and delay > 0:
            time.sleep(delay)
    shutil.rmtree(target, ignore_errors=True)


try:
    import orca  # type: ignore
except ImportError:
    orca = None

if orca is not None:
    from . import plugin  # noqa: F401
