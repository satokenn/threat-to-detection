"""Models and YAML loading for the target system threat model."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Software:
    name: str
    version: str
    cpe: str | None = None


@dataclass(frozen=True)
class Asset:
    name: str
    type: str
    software: tuple[Software, ...] = ()
    exposed_to: tuple[str, ...] = ()
    logs: tuple[str, ...] = ()


@dataclass(frozen=True)
class Flow:
    source: str
    destination: str
    protocol: str | None = None


@dataclass(frozen=True)
class SystemModel:
    assets: tuple[Asset, ...] = ()
    flows: tuple[Flow, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


def load_system(path: str | Path) -> SystemModel:
    """Load and validate a system model from YAML."""
    with Path(path).open(encoding="utf-8") as stream:
        document = yaml.safe_load(stream) or {}

    system = document.get("system", document)
    if not isinstance(system, dict):
        raise ValueError("YAML must contain a 'system' mapping")

    assets = tuple(_asset(item) for item in system.get("assets", []))
    flows = tuple(_flow(item) for item in system.get("flows", []))
    return SystemModel(assets=assets, flows=flows, metadata=system.get("metadata", {}))


def _asset(item: Any) -> Asset:
    if not isinstance(item, dict) or not item.get("name"):
        raise ValueError("Each asset must have a name")
    software = tuple(
        Software(name=str(entry["name"]), version=str(entry["version"]), cpe=entry.get("cpe"))
        for entry in item.get("software", [])
    )
    return Asset(
        name=str(item["name"]),
        type=str(item.get("type", "unknown")),
        software=software,
        exposed_to=tuple(str(value) for value in item.get("exposed_to", [])),
        logs=tuple(str(value) for value in item.get("logs", [])),
    )


def _flow(item: Any) -> Flow:
    if not isinstance(item, dict) or not item.get("from") or not item.get("to"):
        raise ValueError("Each flow must have 'from' and 'to'")
    return Flow(source=str(item["from"]), destination=str(item["to"]), protocol=item.get("protocol"))
