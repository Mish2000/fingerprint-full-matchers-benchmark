"""Small, durable UTF-8 writers."""

from __future__ import annotations

import csv
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


def _replace(path: Path, write) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            write(handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def write_json_atomic(path: Path, value: Any) -> None:
    _replace(Path(path), lambda h: json.dump(value, h, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) or h.write("\n"))


def write_csv_atomic(path: Path, rows: Iterable[Mapping[str, Any]], columns: Sequence[str]) -> None:
    def write(handle) -> None:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="raise", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    _replace(Path(path), write)
