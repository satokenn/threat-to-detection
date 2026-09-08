"""Small, dependency-free models for generated Sigma rules.

The model intentionally only represents the part of a Sigma rule that this
project can derive from :class:`DetectionRequirement`.  In particular, it
does not pretend to know suspicious values when ATT&CK only describes the
telemetry that should be collected.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SigmaEvidenceRecord:
    """One source record retained in Sigma provenance metadata."""

    source: str | None = None
    source_id: str | None = None
    rationale: str | None = None
    confidence: str | None = None
    url: str | None = None
    cve_ids: tuple[str, ...] = ()
    cwe_ids: tuple[str, ...] = ()
    capec_ids: tuple[str, ...] = ()

    def as_mapping(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for name, value in (
            ("source", self.source),
            ("source_id", self.source_id),
            ("rationale", self.rationale),
            ("confidence", self.confidence),
            ("url", self.url),
        ):
            if value:
                result[name] = value
        for name, values in (
            ("cve_ids", self.cve_ids),
            ("cwe_ids", self.cwe_ids),
            ("capec_ids", self.capec_ids),
        ):
            if values:
                result[name] = list(values)
        return result


@dataclass(frozen=True)
class SigmaEvidence:
    """Structured provenance carried by a generated rule.

    IDs are kept separately because CVE, CWE, and CAPEC identifiers have
    different meanings.  ``references`` is for URLs or other source labels
    supplied by a caller, and ``notes`` preserves context that cannot be
    represented by a Sigma standard field.
    """

    cve_ids: tuple[str, ...] = ()
    cwe_ids: tuple[str, ...] = ()
    capec_ids: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    source: str | None = None
    source_id: str | None = None
    rationale: str | None = None
    confidence: str | None = None
    url: str | None = None
    provenance: tuple[SigmaEvidenceRecord, ...] = ()

    def __post_init__(self) -> None:
        if self.provenance:
            # Keep the legacy scalar accessors useful while retaining all
            # records.  The first record is stable and is never overwritten.
            first = self.provenance[0]
            for name in ("source", "source_id", "rationale", "confidence", "url"):
                if getattr(self, name) is None:
                    object.__setattr__(self, name, getattr(first, name))
            for name in ("cve_ids", "cwe_ids", "capec_ids"):
                values = _unique(
                    (
                        *getattr(self, name),
                        *(value for record in self.provenance for value in getattr(record, name)),
                    )
                )
                object.__setattr__(self, name, values)
        elif any(
            value is not None
            for value in (self.source, self.source_id, self.rationale, self.confidence, self.url)
        ):
            object.__setattr__(
                self,
                "provenance",
                (
                    SigmaEvidenceRecord(
                        source=self.source,
                        source_id=self.source_id,
                        rationale=self.rationale,
                        confidence=self.confidence,
                        url=self.url,
                        cve_ids=self.cve_ids,
                        cwe_ids=self.cwe_ids,
                        capec_ids=self.capec_ids,
                    ),
                ),
            )

    @property
    def cves(self) -> tuple[str, ...]:
        """Compatibility alias for callers that use the shorter name."""

        return self.cve_ids

    @property
    def cwes(self) -> tuple[str, ...]:
        return self.cwe_ids

    @property
    def capecs(self) -> tuple[str, ...]:
        return self.capec_ids

    def as_metadata(self) -> dict[str, Any]:
        """Return evidence in a YAML-safe, explicit metadata shape."""

        metadata: dict[str, Any] = {}
        for name, values in (
            ("cve_ids", self.cve_ids),
            ("cwe_ids", self.cwe_ids),
            ("capec_ids", self.capec_ids),
            ("references", self.references),
            ("notes", self.notes),
        ):
            if values:
                metadata[name] = list(values)
        for name, value in (
            ("source", self.source),
            ("source_id", self.source_id),
            ("rationale", self.rationale),
            ("confidence", self.confidence),
            ("url", self.url),
        ):
            if value:
                metadata[name] = [value]
        if self.provenance:
            metadata["provenance"] = [record.as_mapping() for record in self.provenance]
        return metadata


@dataclass(frozen=True)
class SigmaRule:
    """A minimally complete Sigma rule and its provenance."""

    title: str
    logsource: Mapping[str, str]
    detection: Mapping[str, Any]
    description: str = ""
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    falsepositives: tuple[str, ...] = ()
    level: str = "low"
    status: str = "experimental"
    evidence: SigmaEvidence = field(default_factory=SigmaEvidence)
    rule_id: str | None = None
    rule_kind: str = "detection_candidate"

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        """Perform the minimum structural validation required by Sigma."""

        if not isinstance(self.title, str) or not self.title.strip():
            raise ValueError("Sigma rule title must be a non-empty string")
        if len(self.title) > 256:
            raise ValueError("Sigma rule title must be at most 256 characters")
        if not isinstance(self.logsource, Mapping):
            raise ValueError("Sigma rule logsource must be a mapping")
        if any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in self.logsource.items()
        ):
            raise ValueError("Sigma logsource keys and values must be strings")
        required_logsource_keys = {"category", "product", "service"}
        if not any(
            key in self.logsource
            and isinstance(self.logsource[key], str)
            and self.logsource[key].strip()
            for key in required_logsource_keys
        ):
            raise ValueError("Sigma logsource needs a non-empty category, product, or service")
        if not isinstance(self.detection, Mapping) or not self.detection:
            raise ValueError("Sigma rule detection must be a non-empty mapping")
        condition = self.detection.get("condition")
        if not isinstance(condition, str) or not condition.strip():
            raise ValueError("Sigma rule detection must contain a non-empty condition")
        selectors = [key for key in self.detection if key != "condition"]
        if not selectors:
            raise ValueError("Sigma rule detection must contain at least one selector")
        for selector in selectors:
            if not isinstance(selector, str) or not selector.strip():
                raise ValueError("Sigma detection selector names must be non-empty strings")
            if self.detection[selector] in (None, "", {}, []):
                raise ValueError(f"Sigma detection selector {selector!r} must not be empty")
        for name in ("tags", "references", "falsepositives"):
            values = getattr(self, name)
            if isinstance(values, (str, bytes)) or not isinstance(values, (tuple, list)):
                raise ValueError(f"Sigma {name} must be a sequence of strings")
            if any(not isinstance(value, str) or not value.strip() for value in values):
                raise ValueError(f"Sigma {name} must contain non-empty strings")
        if not isinstance(self.description, str):
            raise ValueError("Sigma description must be a string")
        if not isinstance(self.level, str) or self.level not in {
            "informational",
            "low",
            "medium",
            "high",
            "critical",
        }:
            raise ValueError(f"Unsupported Sigma level: {self.level!r}")
        if not isinstance(self.status, str) or self.status not in {
            "deprecated",
            "unsupported",
            "experimental",
            "test",
            "stable",
        }:
            raise ValueError(f"Unsupported Sigma status: {self.status!r}")
        if self.rule_id is not None and (
            not isinstance(self.rule_id, str) or not self.rule_id.strip()
        ):
            raise ValueError("Sigma rule id must be a non-empty string when provided")
        if self.rule_kind not in {
            "telemetry_validation",
            "detection_candidate",
            "reviewed_rule",
            "production_approved",
        }:
            raise ValueError(f"Unsupported Sigma rule kind: {self.rule_kind!r}")

    def to_mapping(self, *, include_evidence: bool = True) -> dict[str, Any]:
        """Return a YAML-safe mapping in the conventional Sigma field order."""

        result: dict[str, Any] = {
            "title": self.title,
            "logsource": dict(self.logsource),
            "detection": dict(self.detection),
        }
        if self.rule_id:
            result["id"] = self.rule_id
        if self.description:
            result["description"] = self.description
        if self.tags:
            result["tags"] = list(self.tags)
        all_references = _unique((*self.references, *self.evidence.references))
        if all_references:
            result["references"] = list(all_references)
        if self.falsepositives:
            result["falsepositives"] = list(self.falsepositives)
        result["level"] = self.level
        result["status"] = self.status
        evidence = self.evidence.as_metadata()
        evidence["rule_kind"] = self.rule_kind
        if include_evidence and evidence:
            # x_ fields are Sigma's extension namespace and avoid discarding
            # provenance when the YAML is passed between tools.
            result["x_threat_to_detection"] = evidence
        return result


def _unique(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))
