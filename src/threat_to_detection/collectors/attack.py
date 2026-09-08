"""MITRE ATT&CK STIX data acquisition and parsing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from threat_to_detection.models.attack import AttackTechnique
from threat_to_detection.models.detection import (
    DataComponent,
    DetectionAnalytic,
    DetectionRequirement,
    merge_data_components,
)

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)


class AttackDataError(RuntimeError):
    """Raised when ATT&CK STIX data cannot be downloaded or parsed."""


class AttackDataset:
    """Parsed ATT&CK techniques and a CAPEC reverse index."""

    def __init__(
        self,
        techniques: tuple[AttackTechnique, ...],
        requirements: dict[str, tuple[DetectionRequirement, ...]] | None = None,
    ) -> None:
        self.techniques = techniques
        self._by_capec: dict[str, tuple[AttackTechnique, ...]] = {}
        for technique in techniques:
            for capec_id in technique.related_capec_ids:
                self._by_capec.setdefault(capec_id, ())
                self._by_capec[capec_id] += (technique,)
        self._requirements_by_technique = requirements or {}

    @classmethod
    def from_json(cls, path: str | Path) -> "AttackDataset":
        try:
            document = json.loads(Path(path).read_text(encoding="utf-8"))
            objects = document["objects"]
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
            raise AttackDataError(f"Could not parse ATT&CK STIX JSON: {path}") from error
        if not isinstance(objects, list) or not all(isinstance(item, dict) for item in objects):
            raise AttackDataError("ATT&CK STIX bundle must contain an object list")
        try:
            techniques = tuple(
                _parse_technique(item)
                for item in objects
                if item.get("type") == "attack-pattern"
                and not item.get("revoked", False)
                and not item.get("x_mitre_deprecated", False)
            )
        except (TypeError, ValueError) as error:
            raise AttackDataError("Invalid ATT&CK attack-pattern object") from error
        return cls(techniques, _parse_detection_requirements(objects))

    def for_capec(self, capec_id: str) -> tuple[AttackTechnique, ...]:
        """Return all techniques externally mapped to a CAPEC ID."""
        return self._by_capec.get(_normalize_capec(capec_id), ())

    def detection_requirements_for_technique(
        self, technique_id: str
    ) -> tuple[DetectionRequirement, ...]:
        """Return all ATT&CK detection strategies for a technique."""
        if not isinstance(technique_id, str):
            return ()
        return self._requirements_by_technique.get(technique_id.strip().upper(), ())


class AttackCollector:
    """Download the Enterprise ATT&CK STIX bundle and load it."""

    def __init__(self, url: str = ATTACK_STIX_URL, timeout: float = 30.0) -> None:
        self.url = url
        self.timeout = timeout

    def download(self, destination: str | Path) -> Path:
        destination = Path(destination)
        try:
            with urlopen(self.url, timeout=self.timeout) as response:  # noqa: S310 - configured URL
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(response.read())
        except (HTTPError, URLError, OSError) as error:
            raise AttackDataError(f"Could not download ATT&CK STIX data from {self.url}") from error
        return destination

    def load(self, path: str | Path) -> AttackDataset:
        return AttackDataset.from_json(path)


def _parse_technique(item: dict[str, Any]) -> AttackTechnique:
    technique_id, related_capec_ids = _external_references(item.get("external_references", []))
    if not technique_id or not item.get("name"):
        raise ValueError("ATT&CK technique is missing an external ID or name")
    return AttackTechnique(
        technique_id=technique_id,
        name=item["name"],
        description=item.get("description", ""),
        tactics=tuple(
            phase["phase_name"]
            for phase in item.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
            and phase.get("phase_name")
        ),
        related_capec_ids=tuple(related_capec_ids),
    )


def _external_references(references: Any) -> tuple[str | None, list[str]]:
    technique_id = None
    capec_ids: list[str] = []
    if not isinstance(references, list):
        return None, []
    for reference in references:
        if not isinstance(reference, dict):
            continue
        source_name = str(reference.get("source_name", "")).lower()
        external_id = reference.get("external_id")
        if not isinstance(external_id, str):
            continue
        if source_name == "mitre-attack" and external_id.upper().startswith("T"):
            technique_id = external_id.upper()
        if source_name == "capec" and external_id:
            capec_ids.append(_normalize_capec(str(external_id)))
    return technique_id, list(dict.fromkeys(capec_ids))


def _normalize_capec(capec_id: str) -> str:
    value = capec_id.strip().upper()
    return value if value.startswith("CAPEC-") else f"CAPEC-{value}"


def _parse_detection_requirements(
    objects: list[dict[str, Any]]
) -> dict[str, tuple[DetectionRequirement, ...]]:
    by_id = {
        item["id"]: item
        for item in objects
        if isinstance(item.get("id"), str) and item["id"]
    }
    analytics = {
        item["id"]: _parse_analytic(item, by_id)
        for item in objects
        if item.get("type") == "x-mitre-analytic"
        and isinstance(item.get("id"), str)
        and not item.get("revoked", False)
        and not item.get("x_mitre_deprecated", False)
    }
    strategies = {
        item["id"]: item
        for item in objects
        if item.get("type") == "x-mitre-detection-strategy"
        and isinstance(item.get("id"), str)
        and not item.get("revoked", False)
        and not item.get("x_mitre_deprecated", False)
    }
    technique_ids = {
        item["id"]: _external_references(item.get("external_references", []))[0]
        for item in objects
        if item.get("type") == "attack-pattern"
        and isinstance(item.get("id"), str)
        and not item.get("revoked", False)
        and not item.get("x_mitre_deprecated", False)
    }
    result: dict[str, dict[str, DetectionRequirement]] = {}
    for relationship in objects:
        if (
            relationship.get("type") != "relationship"
            or relationship.get("relationship_type") != "detects"
            or relationship.get("revoked", False)
            or relationship.get("x_mitre_deprecated", False)
        ):
            continue
        source_ref = relationship.get("source_ref")
        target_ref = relationship.get("target_ref")
        if not isinstance(source_ref, str) or not isinstance(target_ref, str):
            continue
        strategy = strategies.get(source_ref)
        technique_id = technique_ids.get(target_ref)
        if not strategy or not technique_id:
            continue
        strategy_id = _external_id(strategy.get("external_references", []))
        if not strategy_id:
            strategy_id = _stix_id(strategy.get("id"), "x-mitre-detection-strategy")
        if not strategy_id:
            continue
        analytic_refs = strategy.get("x_mitre_analytic_refs", [])
        if not isinstance(analytic_refs, list):
            analytic_refs = []
        analytic_items = tuple(
            analytics[ref]
            for ref in dict.fromkeys(ref for ref in analytic_refs if isinstance(ref, str))
            if ref in analytics
        )
        result.setdefault(technique_id.upper(), {})[strategy_id] = DetectionRequirement(
            technique_id=technique_id.upper(),
            strategy_id=strategy_id,
            strategy_name=(
                strategy.get("name")
                if isinstance(strategy.get("name"), str) and strategy.get("name")
                else strategy_id
            ),
            analytics=analytic_items,
        )
    return {key: tuple(value.values()) for key, value in result.items()}


def _parse_analytic(item: dict[str, Any], by_id: dict[str, dict[str, Any]]) -> DetectionAnalytic:
    analytic_id = _external_id(item.get("external_references", []))
    components = []
    if not analytic_id:
        analytic_id = item["id"]
    events = []
    references = item.get("x_mitre_log_source_references", [])
    if not isinstance(references, list):
        references = []
    for reference in references:
        if not isinstance(reference, dict):
            continue
        component = by_id.get(reference.get("x_mitre_data_component_ref"))
        if not _is_active(component, "x-mitre-data-component"):
            component = None
        else:
            component_id = _external_id(component.get("external_references", []))
            component_id = component_id or _stix_id(component.get("id"), "x-mitre-data-component")
            component_name_value = component.get("name")
            if component_name_value is not None and not isinstance(component_name_value, str):
                component = None
                component_name = None
            else:
                component_name = component_name_value or component_id
            if not component_id or not component_name:
                component = None
        if component:
            components.append(
                DataComponent(
                    component_id=component_id,
                    name=component_name,
                    data_source_id=_data_source_id(component, by_id),
                    data_source_name=_data_source_name(component, by_id),
                    log_sources=tuple(
                        value
                        for value in (reference.get("name"),)
                        if isinstance(value, str) and value
                    ),
                )
            )
        event = reference.get("channel") or reference.get("event")
        if isinstance(event, str) and event:
            events.append(event)
    mutable_elements = item.get("x_mitre_mutable_elements", [])
    if not isinstance(mutable_elements, list):
        mutable_elements = []
    fields = tuple(
        element["field"]
        for element in mutable_elements
        if isinstance(element, dict)
        and isinstance(element.get("field"), str)
        and element["field"]
    )
    return DetectionAnalytic(
        analytic_id=analytic_id,
        name=(item.get("name") if isinstance(item.get("name"), str) else None)
        or analytic_id,
        description=(
            item.get("description")
            if isinstance(item.get("description"), str)
            else ""
        ),
        data_components=merge_data_components(components),
        events=tuple(dict.fromkeys(events)),
        fields=tuple(dict.fromkeys(fields)),
    )


def _external_id(references: Any) -> str | None:
    """Return the ATT&CK external ID regardless of object type."""
    if not isinstance(references, list):
        return None
    for reference in references:
        if not isinstance(reference, dict):
            continue
        if str(reference.get("source_name", "")).lower() == "mitre-attack":
            external_id = reference.get("external_id")
            if isinstance(external_id, str) and external_id:
                return external_id.upper()
    return None


def _stix_id(value: Any, expected_type: str) -> str | None:
    """Return a valid-enough STIX object ID for a fallback identifier."""
    if not isinstance(value, str) or not value.startswith(f"{expected_type}--"):
        return None
    return value


def _is_active(value: Any, expected_type: str) -> bool:
    return (
        isinstance(value, dict)
        and value.get("type") == expected_type
        and not value.get("revoked", False)
        and not value.get("x_mitre_deprecated", False)
    )


def _data_source_id(
    component: dict[str, Any], by_id: dict[str, dict[str, Any]]
) -> str | None:
    reference = component.get("x_mitre_data_source_ref")
    if not isinstance(reference, str):
        return None
    source = by_id.get(reference)
    if not source:
        return reference
    if not _is_active(source, "x-mitre-data-source"):
        return None
    return _external_id(source.get("external_references", [])) or reference


def _data_source_name(
    component: dict[str, Any], by_id: dict[str, dict[str, Any]]
) -> str | None:
    reference = component.get("x_mitre_data_source_ref")
    if not isinstance(reference, str):
        return None
    source = by_id.get(reference)
    if _is_active(source, "x-mitre-data-source"):
        name = source.get("name")
        return name if isinstance(name, str) and name else None
    return None
