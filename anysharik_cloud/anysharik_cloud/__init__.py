"""AnySharik Cloud OrcaSlicer plugin package."""

from __future__ import annotations

import importlib
import os
import re
import shutil
import stat
import sys
import time
import zipfile
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


def _wheel_sort_key(path: Path):
    parts = path.name.split("-", 2)
    ver_str = parts[1] if len(parts) > 1 else ""
    nums = tuple(int(x) for x in re.findall(r"\d+", ver_str))
    try:
        mtime = path.stat().st_mtime
    except OSError:
        mtime = 0.0
    return (nums, mtime)


def _sync_extracted_wheel(root: Path | None = None) -> bool:
    """Sync __whl_extracted__ Python files from the newest .whl in parent plugin dir.

    Returns True if __init__.py itself was updated and reloaded.
    """
    try:
        pkg_root = (root or Path(__file__).resolve().parent)
        extracted_dir = next((p for p in pkg_root.parents if p.name == "__whl_extracted__"), None)
        if extracted_dir is None:
            return False

        for stale in pkg_root.glob("login_profile*"):
            if stale.is_dir():
                _remove_tree(stale, retries=1, delay=0.0)

        data_dir = extracted_dir.parent
        wheels = list(data_dir.glob("anysharik_cloud-*.whl"))
        if not wheels:
            return False

        wheel_path = max(wheels, key=_wheel_sort_key)
        updates = []
        with zipfile.ZipFile(wheel_path, "r") as zf:
            for member in zf.namelist():
                if not member.startswith("anysharik_cloud/") or not member.endswith(".py"):
                    continue
                rel_name = member.split("/", 1)[1]
                if "/" in rel_name or not rel_name:
                    continue
                payload = zf.read(member)
                target = pkg_root / rel_name
                try:
                    current = target.read_bytes()
                except OSError:
                    current = None
                if current != payload:
                    updates.append((target, payload, rel_name))

        if not updates:
            return False

        for target, payload, _ in updates:
            target.write_bytes(payload)
        _remove_tree(pkg_root / "__pycache__", retries=1, delay=0.0)

        if any(rel_name == "__init__.py" for _, _, rel_name in updates) and __name__ in sys.modules:
            importlib.reload(sys.modules[__name__])
            return True
    except Exception:
        pass
    return False


_reloaded = _sync_extracted_wheel()

if not _reloaded:
    try:
        import orca  # type: ignore
    except ImportError:
        orca = None

    if orca is not None:
        from . import plugin  # noqa: F401
