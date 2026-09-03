"""Threat and evidence models."""

from dataclasses import dataclass


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
