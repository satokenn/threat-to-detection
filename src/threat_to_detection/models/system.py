"""Pydantic models and YAML loading for the target system threat model."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from threat_to_detection.models.scenario import (
    ScenarioContext,
)


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


def _non_empty_optional(value: str | None, field_name: str) -> str | None:
    if value is not None and not value.strip():
        raise ValueError(f"{field_name} must not be empty")
    return value


class AuthenticationCondition(BaseModel):
    """Authentication prerequisites for a data flow.

    An omitted field means that the scenario did not specify the condition;
    it must not be interpreted as an unauthenticated flow.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")
    required: StrictBool = False
    method: str | None = None
    principal: str | None = None
    identity_source: str | None = None

    @field_validator("method", "principal", "identity_source")
    @classmethod
    def validate_text(cls, value: str | None, info: Any) -> str | None:
        return _non_empty_optional(value, info.field_name)


class AuthorizationCondition(BaseModel):
    """Authorization prerequisites for a data flow."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    required: StrictBool = False
    roles: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()
    privilege: str | None = None

    @field_validator("roles", "scopes", mode="before")
    @classmethod
    def validate_sequences(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            value = (value,)
        if not isinstance(value, (list, tuple, set)):
            raise ValueError("roles/scopes must be strings or lists of strings")
        if any(not isinstance(item, str) or not item.strip() for item in value):
            raise ValueError("roles/scopes must contain non-empty strings")
        return tuple(dict.fromkeys(item.strip() for item in value))

    @field_validator("privilege")
    @classmethod
    def validate_privilege(cls, value: str | None) -> str | None:
        return _non_empty_optional(value, "privilege")


class Asset(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    name: str
    type: str = "unknown"
    software: tuple[Software, ...] = ()
    exposed_to: tuple[str, ...] = ()
    logs: tuple[str, ...] = ()
    logsource: dict[str, str] | None = None
    trust_zone: str | None = None
    privilege_level: str | None = None

    @field_validator("trust_zone", "privilege_level")
    @classmethod
    def validate_security_labels(cls, value: str | None, info: Any) -> str | None:
        return _non_empty_optional(value, info.field_name)


class Flow(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True, extra="forbid")
    source: str = Field(validation_alias="from")
    destination: str = Field(validation_alias="to")
    protocol: str | None = None
    trust_boundary: str | None = None
    authentication: AuthenticationCondition | None = None
    authorization: AuthorizationCondition | None = None

    @field_validator("source", "destination", "protocol", "trust_boundary")
    @classmethod
    def validate_flow_text(cls, value: str | None, info: Any) -> str | None:
        if value is None and info.field_name in {"source", "destination"}:
            raise ValueError(f"{info.field_name} must not be empty")
        return _non_empty_optional(value, info.field_name)


class SystemModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    assets: tuple[Asset, ...] = ()
    flows: tuple[Flow, ...] = ()
    metadata: dict[str, Any] = {}
    scenario: ScenarioContext = Field(default_factory=ScenarioContext)

    @model_validator(mode="before")
    @classmethod
    def accept_flat_scenario_fields(cls, values: Any) -> Any:
        """Accept both ``scenario:`` and the legacy-friendly flat form.

        Existing scenario files only contain assets/flows and therefore keep
        the vulnerability/CVE defaults.  New multi-domain files may use a
        nested ``scenario`` block, while flat ``scenario_type`` fields remain
        convenient for small fixtures.
        """
        if not isinstance(values, dict):
            return values
        values = dict(values)
        scenario = values.get("scenario")
        flat_keys = {
            "scenario_type",
            "entrypoint_type",
            "entrypoint",
            "weakness_ids",
            "attack_pattern_ids",
            "attacker_actions",
            "technique_ids",
            "required_telemetry",
            "available_telemetry",
            "evidence",
            "rationale",
            "confidence",
            "required_privilege",
            "privilege_transition",
            "required_authentication_logs",
        }
        flat = {key: values.pop(key) for key in flat_keys if key in values}
        if flat:
            if scenario is not None and not isinstance(scenario, dict):
                raise ValueError("scenario must be a mapping")
            merged = dict(scenario or {})
            merged.update(flat)
            values["scenario"] = merged
        return values

    @model_validator(mode="after")
    def validate_asset_names(self) -> "SystemModel":
        names = tuple(asset.name.strip() for asset in self.assets)
        if any(not name for name in names):
            raise ValueError("asset names must not be empty")
        if len(set(names)) != len(names):
            raise ValueError("asset names must be unique")
        return self

    @property
    def scenario_type(self) -> str:
        """Compatibility-friendly access to the scenario domain."""

        return self.scenario.scenario_type

    @property
    def entrypoint_type(self) -> str:
        return self.scenario.entrypoint_type


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
    # The multi-domain evaluation catalog uses a scenario-focused document
    # without a full asset inventory.  Adapt that explicit format into the
    # common model with one synthetic, named scenario asset; this is safe
    # telemetry metadata only and does not execute a payload.
    if "system" not in document and "scenario_type" in document:
        system = _scenario_document_to_system(document)
    # Permit a readable top-level scenario block alongside the existing
    # ``system:`` document shape.  The nested form remains authoritative when
    # both are present.
    if isinstance(document, dict) and "scenario" in document and "scenario" not in system:
        system = dict(system)
        system["scenario"] = document["scenario"]
    try:
        return SystemModel.model_validate(system)
    except ValueError as error:
        raise ValueError(f"Invalid system model: {error}") from error


def _scenario_document_to_system(document: dict[str, Any]) -> dict[str, Any]:
    entrypoint = document.get("entrypoint")
    if not isinstance(entrypoint, dict):
        raise ValueError("scenario document must contain an entrypoint mapping")
    identifiers = entrypoint.get("identifiers")
    if not isinstance(identifiers, dict):
        identifiers = {}
    analysis_chain = document.get("analysis_chain")
    if not isinstance(analysis_chain, dict):
        analysis_chain = {}
    required_logs = analysis_chain.get("required_logs", ())
    required_telemetry = []
    if isinstance(required_logs, list):
        for item in required_logs:
            if isinstance(item, dict) and isinstance(item.get("event_type"), str):
                required_telemetry.append(item["event_type"])
    scenario_type = document["scenario_type"]
    # Vulnerability scenarios list ATT&CK IDs as expected/reference outcomes,
    # but those IDs must be reached through CVE→CWE→CAPEC→ATT&CK.  Treating
    # them as an independent entrypoint would duplicate traces and gaps.
    direct_techniques = () if scenario_type == "vulnerability" else _as_sequence(
        identifiers.get("attack_techniques")
    )
    scenario = {
        "scenario_type": scenario_type,
        "entrypoint_type": entrypoint.get("type"),
        "entrypoint": entrypoint,
        "weakness_ids": _as_sequence(identifiers.get("cwe")),
        "attack_pattern_ids": _as_sequence(identifiers.get("capec")),
        "technique_ids": direct_techniques,
        "attacker_actions": _as_sequence(analysis_chain.get("attacker_action")),
        "required_telemetry": tuple(required_telemetry),
        "available_telemetry": tuple(document.get("available_logs", ())),
        "evidence": tuple(document.get("evidence", {}).get("fixture_backed_ids", ()))
        if isinstance(document.get("evidence"), dict)
        else (),
        "rationale": str(analysis_chain.get("monitoring", "")),
        "required_privilege": analysis_chain.get("required_privilege"),
        "privilege_transition": analysis_chain.get("privilege_transition"),
        "required_authentication_logs": _as_sequence(
            analysis_chain.get("required_authentication_logs")
        ),
    }
    scenario_id = document.get("scenario_id", "scenario")
    title = document.get("title", "")
    declared_asset = document.get("asset")
    if declared_asset is not None and not isinstance(declared_asset, dict):
        raise ValueError("scenario asset must be a mapping")
    if isinstance(declared_asset, dict):
        asset = dict(declared_asset)
        asset.setdefault("name", scenario_id)
        asset.setdefault("type", scenario_type)
        asset.setdefault("logs", list(document.get("available_logs", ())))
        if "software" not in asset and isinstance(document.get("software"), list):
            asset["software"] = document["software"]
    else:
        asset = {
            "name": scenario_id,
            "type": scenario_type,
            "logs": list(document.get("available_logs", ())),
        }
        if isinstance(document.get("software"), list):
            asset["software"] = document["software"]
    return {
        "metadata": {"name": scenario_id, "description": title},
        "scenario": scenario,
        "assets": [asset],
    }


def _as_sequence(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(item for item in value if isinstance(item, str) and item)
    return ()


def _cpe_component(value: str) -> str:
    value = value.strip().lower().replace(" ", "_")
    if not value or any(character in value for character in (":", "\\", "/")):
        raise ValueError("CPE components must not contain ':', '\\', or '/'")
    return value
