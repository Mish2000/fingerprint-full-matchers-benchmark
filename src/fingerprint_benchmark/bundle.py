"""Atomic directory publication."""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path
from typing import Callable


def publish_bundle(candidate: Path, destination: Path, validate: Callable[[Path], None], replace: bool = False) -> Path:
    candidate = Path(candidate)
    destination = Path(destination)
    validate(candidate)
    if destination.exists() and not replace:
        validate(destination)
        shutil.rmtree(candidate)
        return destination
    backup = destination.with_name(f"{destination.name}.rollback-{uuid.uuid4().hex}")
    moved_old = False
    published_candidate = False
    try:
        if destination.exists():
            os.replace(destination, backup)
            moved_old = True
        os.replace(candidate, destination)
        published_candidate = True
        validate(destination)
        if moved_old:
            shutil.rmtree(backup)
        return destination
    except BaseException:
        if destination.exists() and published_candidate:
            shutil.rmtree(destination)
        if moved_old and backup.exists():
            os.replace(backup, destination)
        raise
