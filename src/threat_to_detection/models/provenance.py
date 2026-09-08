"""Reproducibility metadata for acquired and generated artifacts."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DataSnapshot:
    """Describe the exact data representation used by one collector."""

    source: str
    mode: str
    url: str | None = None
    path: str | None = None
    release: str | None = None
    retrieved_at: str | None = None
    sha: str | None = None
    raw_sha256: str | None = None
    normalization: tuple[str, ...] = ()
    exclusions: tuple[str, ...] = ()
    records: tuple[dict[str, Any], ...] = ()

    def to_mapping(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "source": self.source,
            "mode": self.mode,
            "url": self.url,
            "path": self.path,
            "release": self.release,
            "retrieved_at": self.retrieved_at,
            "retrieved_date": (
                self.retrieved_at[:10]
                if self.retrieved_at and len(self.retrieved_at) >= 10
                and self.retrieved_at[4] == "-"
                else None
            ),
            "sha": self.sha,
            "raw_sha256": self.raw_sha256,
            "normalization": list(self.normalization),
            "exclusions": list(self.exclusions),
        }
        if self.records:
            result["records"] = [dict(record) for record in self.records]
        return result


def file_sha256(path: str | Path) -> str:
    """Hash a source file without loading the complete file into memory."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def display_path(path: str | Path, *, base: str | Path | None = None) -> str:
    """Return a stable, human-readable path for reports and manifests."""
    value = Path(path)
    root = Path(base) if base is not None else Path.cwd()
    try:
        return value.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return value.as_posix()
