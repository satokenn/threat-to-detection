"""Pydantic models and YAML loading for the target system threat model."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Software(BaseModel):
    """A software product and version with a generated CPE 2.3 name."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    vendor: str = "unknown"
    product: str
    version: str
    cpe: str | None = None

    @model_validator(mode="before")
    @classmethod
    def accept_legacy_name(cls, values: Any) -> Any:
        if isinstance(values, dict) and "product" not in values and "name" in values:
            values = dict(values)
            values["product"] = values.pop("name")
        return values

    @model_validator(mode="after")
    def validate_components(self) -> "Software":
        for field_name in ("vendor", "product", "version"):
            if not getattr(self, field_name).strip():
                raise ValueError(f"{field_name} must not be empty")
        if self.cpe and not self.cpe.startswith("cpe:2.3:"):
            raise ValueError("cpe must be a CPE 2.3 formatted name")
        return self

    @property
    def name(self) -> str:
        return self.product

    @property
    def cpe_name(self) -> str:
        return self.cpe or build_cpe(self.vendor, self.product, self.version)


class Asset(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    name: str
    type: str = "unknown"
    software: tuple[Software, ...] = ()
    exposed_to: tuple[str, ...] = ()
    logs: tuple[str, ...] = ()


class Flow(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True, extra="forbid")
    source: str = Field(validation_alias="from")
    destination: str = Field(validation_alias="to")
    protocol: str | None = None


class SystemModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    assets: tuple[Asset, ...] = ()
    flows: tuple[Flow, ...] = ()
    metadata: dict[str, Any] = {}


def build_cpe(vendor: str, product: str, version: str) -> str:
    """Build a CPE 2.3 application name from vendor/product/version."""
    components = (_cpe_component(vendor), _cpe_component(product), _cpe_component(version))
    return f"cpe:2.3:a:{components[0]}:{components[1]}:{components[2]}:*:*:*:*:*:*:*"


def load_system(path: str | Path) -> SystemModel:
    """Load and validate a system model from YAML."""
    with Path(path).open(encoding="utf-8") as stream:
        document = yaml.safe_load(stream) or {}
    system = document.get("system", document)
    if not isinstance(system, dict):
        raise ValueError("YAML must contain a 'system' mapping")
    try:
        return SystemModel.model_validate(system)
    except ValueError as error:
        raise ValueError(f"Invalid system model: {error}") from error


def _cpe_component(value: str) -> str:
    value = value.strip().lower().replace(" ", "_")
    if not value or any(character in value for character in (":", "\\", "/")):
        raise ValueError("CPE components must not contain ':', '\\', or '/'")
    return value
