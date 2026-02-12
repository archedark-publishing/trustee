"""Local storage hardening helpers."""

from __future__ import annotations

import os
import re
from pathlib import Path


_SAFE_ID_RE = re.compile(r"[^a-zA-Z0-9._-]")


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def ensure_private_file(path: Path) -> None:
    if not path.exists():
        path.touch()
    os.chmod(path, 0o600)


def sanitize_identifier(value: str) -> str:
    """Return a filesystem-safe identifier."""
    return _SAFE_ID_RE.sub("_", value)


def safe_child_path(base_dir: Path, identifier: str, suffix: str) -> Path:
    """Build a canonical child path under base_dir and reject traversal."""
    safe_name = sanitize_identifier(identifier)
    path = (base_dir / f"{safe_name}{suffix}").resolve()
    base = base_dir.resolve()
    if path.parent != base:
        raise ValueError(f"Unsafe path for identifier: {identifier}")
    return path
