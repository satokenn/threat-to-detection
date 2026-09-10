"""Threat, evidence, and threat-universe models."""

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, StrictBool, field_validator


@dataclass(frozen=True)
class Evidence:
    source: str
    source_id: str
    rationale: str = ""
    confidence: str = "unknown"
    url: str | None = None


@dataclass(frozen=True)
class ThreatCandidate:
    name: str
    attack_technique_ids: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()


class ThreatSource(BaseModel):
    """A source record for a candidate and its interpretation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_type: str
    source_id: str
    url: str | None = None
    rationale: str

    @field_validator("source_type", "source_id", "rationale")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("threat source text must not be empty")
        return value.strip()


class ThreatApplicabilityProfile(BaseModel):
    """Candidate-specific prerequisites used by the threat-model selector.

    A missing value means that the candidate's prerequisite is not known.  A
    candidate must explicitly say that a prerequisite is not required with
    ``false``; the evaluator never infers that from a protocol or a flow.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    flow_scope: Literal["network", "local"] = "network"
    flow_direction: Literal["inbound", "outbound", "either"] = "inbound"
    flow_source: str | None = None
    protocol: str | None = None
    trust_boundary_required: StrictBool | None = None
    required_trust_boundary: str | None = None
    authentication_required: StrictBool | None = None
    authorization_required: StrictBool | None = None
    privilege_required: StrictBool | None = None
    required_privilege: str | None = None
    required_preconditions: tuple[str, ...] = ()
    rationale: str

    @field_validator("flow_source", "protocol", "required_trust_boundary", "required_privilege")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("threat applicability text must not be empty")
        return value.strip() if value is not None else None

    @field_validator("required_preconditions", mode="before")
    @classmethod
    def normalize_preconditions(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            value = (value,)
        if not isinstance(value, (list, tuple, set)):
            raise ValueError("required_preconditions must be a string or sequence")
        result = tuple(item.strip() for item in value if isinstance(item, str) and item.strip())
        if len(result) != len(value):
            raise ValueError("required_preconditions must contain non-empty strings")
        return tuple(dict.fromkeys(result))

    @field_validator("rationale")
    @classmethod
    def validate_rationale(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("threat applicability rationale must not be empty")
        return value.strip()


class ThreatUniverseCandidate(BaseModel):
    """One threat hypothesis in the broad candidate population."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    threat_id: str
    name: str
    domain: str
    attack_technique_ids: tuple[str, ...]
    target_asset: str
    source: ThreatSource
    applicability: ThreatApplicabilityProfile

    @field_validator("threat_id", "name", "domain", "target_asset")
    @classmethod
    def validate_identity_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("threat candidate identity must not be empty")
        return value.strip()

    @field_validator("attack_technique_ids", mode="before")
    @classmethod
    def normalize_technique_ids(cls, value: Any) -> tuple[str, ...]:
        if isinstance(value, str):
            value = (value,)
        if not isinstance(value, (list, tuple, set)) or not value:
            raise ValueError("attack_technique_ids must be a non-empty sequence")
        result = tuple(item.strip() for item in value if isinstance(item, str) and item.strip())
        if len(result) != len(value):
            raise ValueError("attack_technique_ids must contain non-empty strings")
        return tuple(dict.fromkeys(result))


class ThreatUniverseSampling(BaseModel):
    """Reproducible sampling configuration for a threat population."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    method: Literal["stratified_random_without_replacement"]
    seed: int
    sample_per_stratum: int
    strata_field: Literal["domain"] = "domain"

    @field_validator("sample_per_stratum")
    @classmethod
    def validate_sample_size(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("sample_per_stratum must be positive")
        return value


class ThreatUniverseExpectedOutcome(BaseModel):
    """Expected result used to validate a committed universe evaluation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sampled_candidate_count: int
    status_counts: dict[str, int]
    selected_threat_ids: tuple[str, ...]


class ThreatUniverse(BaseModel):
    """A broad, source-referenced threat population for offline evaluation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str
    title: str
    purpose: str
    target_system: str
    sampling: ThreatUniverseSampling
    threats: tuple[ThreatUniverseCandidate, ...]
    expected_outcome: ThreatUniverseExpectedOutcome

    @field_validator("schema_version", "title", "purpose", "target_system")
    @classmethod
    def validate_universe_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("threat universe text must not be empty")
        return value.strip()

    @field_validator("threats")
    @classmethod
    def validate_unique_threats(
        cls, value: tuple[ThreatUniverseCandidate, ...]
    ) -> tuple[ThreatUniverseCandidate, ...]:
        ids = [item.threat_id for item in value]
        if not value or len(set(ids)) != len(ids):
            raise ValueError("threat universe must contain unique, non-empty candidates")
        return value
