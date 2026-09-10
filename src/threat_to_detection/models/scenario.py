"""Common threat-scenario input and analysis context models.

The original pipeline starts with a vulnerability.  A detection analysis can
also start with a malware behaviour, an identity event, a network event, or a
cloud event.  These models keep that distinction explicit while leaving the
downstream ATT&CK-to-telemetry stages shared.
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ScenarioType = Literal[
    "vulnerability",
    "malware",
    "identity",
    "network",
    "cloud",
    "control",
]
EntrypointType = Literal[
    "cve",
    "cwe",
    "capec",
    "technique",
    "malware_behavior",
    "campaign",
    "identity_event",
    "identity_behavior",
    "network_event",
    "network_behavior",
    "cloud_event",
    "cloud_behavior",
    "control",
]
Confidence = Literal["unknown", "low", "medium", "high"]


class TelemetryRequirement(BaseModel):
    """An event type and the fields needed to analyse it.

    Keeping the event and field dimensions together prevents a scenario from
    claiming complete coverage merely because an event family exists.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_type: str
    fields: tuple[str, ...] = ()

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("event_type must not be empty")
        return value.strip()

    @field_validator("fields", mode="before")
    @classmethod
    def normalize_fields(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            value = (value,)
        if not isinstance(value, (list, tuple, set)):
            raise ValueError("telemetry fields must be strings or lists of strings")
        if any(not isinstance(item, str) or not item.strip() for item in value):
            raise ValueError("telemetry fields must contain non-empty strings")
        return tuple(dict.fromkeys(item.strip() for item in value))


class ScenarioEntrypoint(BaseModel):
    """The threat knowledge record that starts an analysis."""

    model_config = ConfigDict(frozen=True, extra="allow")

    type: EntrypointType
    id: str | None = None
    name: str | None = None
    description: str = ""
    behaviors: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    @field_validator("id", "name")
    @classmethod
    def non_empty_optional_text(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("entrypoint id/name must not be empty")
        return value


class ScenarioContext(BaseModel):
    """Domain-neutral context shared by vulnerability and non-CVE scenarios."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_type: ScenarioType = "vulnerability"
    entrypoint_type: EntrypointType = "cve"
    entrypoint: ScenarioEntrypoint | None = None
    weakness_ids: tuple[str, ...] = ()
    attack_pattern_ids: tuple[str, ...] = ()
    attacker_actions: tuple[str, ...] = ()
    technique_ids: tuple[str, ...] = ()
    required_telemetry: tuple[str, ...] = ()
    required_logs: tuple[TelemetryRequirement, ...] = ()
    available_telemetry: tuple[str, ...] = ()
    available_log_fields: dict[str, tuple[str, ...]] = {}
    evidence: tuple[str, ...] = ()
    rationale: str = ""
    confidence: Confidence = "unknown"
    required_trust_boundary: str | None = None
    required_privilege: str | None = None
    privilege_transition: str | None = None
    required_authentication_logs: tuple[str, ...] = ()

    @model_validator(mode="before")
    @classmethod
    def infer_entrypoint_type(cls, values: Any) -> Any:
        if not isinstance(values, dict):
            return values
        values = dict(values)
        entrypoint = values.get("entrypoint")
        if "entrypoint_type" not in values and isinstance(entrypoint, dict):
            if isinstance(entrypoint.get("type"), str):
                values["entrypoint_type"] = entrypoint["type"]
        return values

    @field_validator(
        "weakness_ids",
        "attack_pattern_ids",
        "attacker_actions",
        "technique_ids",
        "required_telemetry",
        "available_telemetry",
        "evidence",
        "required_authentication_logs",
        mode="before",
    )
    @classmethod
    def normalize_sequences(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            value = (value,)
        if not isinstance(value, (list, tuple, set)):
            raise ValueError("scenario sequence fields must be strings or lists of strings")
        result = tuple(item.strip() for item in value if isinstance(item, str) and item.strip())
        if len(result) != len(value):
            raise ValueError("scenario sequence fields must contain non-empty strings")
        return tuple(dict.fromkeys(result))

    @field_validator("required_logs", mode="before")
    @classmethod
    def normalize_log_requirements(cls, value: Any) -> tuple[TelemetryRequirement, ...]:
        if value is None:
            return ()
        if not isinstance(value, (list, tuple)):
            raise ValueError("required_logs must be a list of mappings")
        result: list[TelemetryRequirement] = []
        for item in value:
            if isinstance(item, str):
                item = {"event_type": item}
            if not isinstance(item, dict):
                raise ValueError("required_logs must contain mappings")
            requirement = TelemetryRequirement.model_validate(item)
            if requirement not in result:
                result.append(requirement)
        return tuple(result)

    @field_validator("available_log_fields", mode="before")
    @classmethod
    def normalize_available_log_fields(cls, value: Any) -> dict[str, tuple[str, ...]]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError("available_log_fields must be a mapping")
        result: dict[str, tuple[str, ...]] = {}
        for event_type, fields in value.items():
            requirement = TelemetryRequirement.model_validate(
                {"event_type": event_type, "fields": fields}
            )
            result[requirement.event_type] = requirement.fields
        return result

    @field_validator("rationale")
    @classmethod
    def normalize_rationale(cls, value: str) -> str:
        return value.strip()

    @field_validator(
        "required_trust_boundary", "required_privilege", "privilege_transition"
    )
    @classmethod
    def validate_optional_security_text(cls, value: str | None, info: Any) -> str | None:
        if value is not None and not value.strip():
            raise ValueError(f"{info.field_name} must not be empty")
        return value.strip() if value is not None else None

    def model_post_init(self, __context: Any) -> None:
        if self.entrypoint is not None and self.entrypoint.type != self.entrypoint_type:
            raise ValueError(
                "entrypoint_type must match entrypoint.type "
                f"({self.entrypoint_type!r} != {self.entrypoint.type!r})"
            )
        if self.scenario_type == "vulnerability" and self.entrypoint_type != "cve":
            raise ValueError("vulnerability scenarios must use a cve entrypoint")
        if self.scenario_type == "malware" and self.entrypoint_type not in {
            "malware_behavior",
            "campaign",
            "technique",
        }:
            raise ValueError(
                "malware scenarios need a malware_behavior, campaign, or technique entrypoint"
            )
        if self.scenario_type == "identity" and self.entrypoint_type not in {
            "identity_event",
            "identity_behavior",
            "technique",
        }:
            raise ValueError("identity scenarios need an identity_event or technique entrypoint")
        if self.scenario_type == "network" and self.entrypoint_type not in {
            "network_event",
            "network_behavior",
            "technique",
        }:
            raise ValueError("network scenarios need a network_event or technique entrypoint")
        if self.scenario_type == "cloud" and self.entrypoint_type not in {
            "cloud_event",
            "cloud_behavior",
            "technique",
        }:
            raise ValueError("cloud scenarios need a cloud_event or technique entrypoint")
        if self.scenario_type == "control" and self.entrypoint_type != "control":
            raise ValueError("control scenarios need a control entrypoint")


class TelemetryCoverage(BaseModel):
    """Comparison of required telemetry with logs available on an asset."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    required: tuple[str, ...] = ()
    available: tuple[str, ...] = ()
    covered: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    coverage_ratio: float = Field(ge=0.0, le=1.0)

    @classmethod
    def from_values(
        cls, required: tuple[str, ...], available: tuple[str, ...]
    ) -> "TelemetryCoverage":
        available_set = {value.casefold() for value in available}
        covered = tuple(value for value in required if value.casefold() in available_set)
        missing = tuple(value for value in required if value.casefold() not in available_set)
        ratio = len(covered) / len(required) if required else 1.0
        return cls(
            required=required,
            available=available,
            covered=covered,
            missing=missing,
            coverage_ratio=ratio,
        )
