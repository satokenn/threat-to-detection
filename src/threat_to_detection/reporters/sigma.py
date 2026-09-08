"""Generate and serialize conservative Sigma rules."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

import yaml

from threat_to_detection.models.detection import DetectionRequirement
from threat_to_detection.models.sigma import SigmaEvidence, SigmaEvidenceRecord, SigmaRule


_EVENT_ID = re.compile(r"^event\s*id\s*[:=]?\s*(\d+)$", re.IGNORECASE)

# ATT&CK data-component names are not Sigma logsource categories.  Keep only
# explicit, reviewed normalizations: fuzzy substring matching can silently
# select the wrong telemetry source.
_LOGSOURCE_MAP = {
    "process creation": {"category": "process_creation"},
    "process execution": {"category": "process_creation"},
    "file access": {"category": "file_event"},
    "file activity": {"category": "file_event"},
    "file and directory discovery": {"category": "file_event"},
    "network connection creation": {"category": "network_connection"},
    "network connection": {"category": "network_connection"},
    "network traffic": {"category": "network_connection"},
    "dns query": {"category": "dns"},
    "registry key modification": {"category": "registry_event"},
    "registry": {"category": "registry_event"},
    "authentication": {"category": "authentication"},
    "logon": {"category": "authentication"},
    "powershell": {"category": "ps_script"},
    "windows event log": {"product": "windows"},
    "sysmon": {"service": "sysmon"},
}


def _unique(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


def detection_requirement_to_sigma(
    requirement: DetectionRequirement,
    *,
    evidence: SigmaEvidence | Mapping[str, Any] | Iterable[Any] | Any | None = None,
    cve_ids: tuple[str, ...] = (),
    cwe_ids: tuple[str, ...] = (),
    capec_ids: tuple[str, ...] = (),
    references: tuple[str, ...] = (),
    notes: tuple[str, ...] = (),
    logsource: Mapping[str, str] | None = None,
    logsource_override: Mapping[str, str] | None = None,
    title: str | None = None,
    description: str | None = None,
    level: str = "low",
    status: str = "experimental",
    falsepositives: tuple[str, ...] = (),
    rule_id: str | None = None,
    rule_kind: str = "detection_candidate",
) -> SigmaRule:
    """Convert one detection requirement into a minimally safe Sigma rule.

    ATT&CK analytic fields describe telemetry, not necessarily malicious
    values.  Therefore fields are emitted with Sigma's ``exists`` modifier,
    while explicit ``Event ID N`` events are retained as exact numeric
    selectors.  Unparseable event labels are retained as provenance and only
    usable fields can produce a selector from them.  A requirement without a
    usable event or field is rejected instead of becoming an all-events rule.
    """

    normalized_evidence = _coerce_evidence(evidence)
    normalized_evidence = _merge_evidence(
        normalized_evidence,
        SigmaEvidence(
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            capec_ids=capec_ids,
            references=references,
            notes=notes,
        ),
    )
    events = requirement.events
    fields = requirement.fields
    if not events and not fields:
        raise ValueError(
            f"Cannot generate Sigma detection for {requirement.technique_id}: "
            "requirement has no event or field evidence"
        )

    selection: dict[str, Any] = {}
    event_ids: list[int] = []
    ambiguous_events: list[str] = []
    for event in events:
        match = _EVENT_ID.match(event.strip())
        if match:
            event_ids.append(int(match.group(1)))
        else:
            # Keep non-standard labels as provenance, without guessing a
            # product-specific field name or turning them into detection.
            ambiguous_events.append(event)
    if event_ids:
        selection["EventID"] = event_ids[0] if len(event_ids) == 1 else event_ids
    for field_name in _normalize_fields(fields):
        selection[f"{field_name}|exists"] = True

    if not selection:
        raise ValueError(
            f"Cannot generate Sigma detection for {requirement.technique_id}: "
            "event labels are not parseable and no fields are available"
        )

    if logsource is not None and logsource_override is not None:
        if dict(logsource) != dict(logsource_override):
            raise ValueError("logsource and logsource_override disagree")
    selected_logsource = logsource_override if logsource_override is not None else logsource
    if selected_logsource is not None:
        selected_logsource = _normalize_logsource(selected_logsource)
    else:
        selected_logsource = _logsource_for(requirement)
    if selected_logsource is None:
        raise ValueError(
            f"Cannot generate Sigma rule for {requirement.technique_id}: "
            "logsource could not be determined from the requirement"
        )
    if ambiguous_events:
        normalized_evidence = _merge_evidence(
            normalized_evidence,
            SigmaEvidence(
                notes=(
                    "Unparsed ATT&CK event labels: "
                    + ", ".join(ambiguous_events),
                )
            ),
        )
    generated_description = _description_for(requirement, ambiguous_events)
    if description:
        generated_description = description
    return SigmaRule(
        title=title or requirement.strategy_name or f"ATT&CK {requirement.technique_id}",
        logsource=selected_logsource,
        detection={"selection": selection, "condition": "selection"},
        description=generated_description,
        tags=(f"attack.{requirement.technique_id.strip().lower()}",),
        references=normalized_evidence.references,
        falsepositives=falsepositives,
        level=level,
        status=status,
        evidence=normalized_evidence,
        rule_id=rule_id,
        rule_kind=rule_kind,
    )


# Short aliases make the reporter convenient without making callers depend on
# an internal implementation name.
to_sigma_rule = detection_requirement_to_sigma
generate_sigma_rule = detection_requirement_to_sigma
sigma_rule_from_detection_requirement = detection_requirement_to_sigma


def render_sigma_yaml(rule: SigmaRule, *, include_evidence: bool = True) -> str:
    """Serialize a validated rule as stable, human-readable YAML."""

    rule.validate()
    return yaml.safe_dump(
        rule.to_mapping(include_evidence=include_evidence),
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )


serialize_sigma = render_sigma_yaml
to_yaml = render_sigma_yaml


def logsource_for_detection_requirement(
    requirement: DetectionRequirement,
) -> dict[str, str] | None:
    """Return an explicit logsource mapping when the telemetry name is known."""
    return _logsource_for(requirement)


def sigma_rule_matches_event(rule: SigmaRule, event: Mapping[str, Any]) -> bool:
    """Evaluate the conservative selector emitted by this reporter.

    This is intentionally a small fixture evaluator, not a replacement for a
    SIEM or a complete Sigma backend.  It supports the two predicates this
    project generates: exact ``EventID`` values and ``|exists`` fields.
    """
    selection = rule.detection.get("selection")
    if not isinstance(selection, Mapping):
        return False
    return all(_selector_matches(event, key, value) for key, value in selection.items())


def _selector_matches(event: Mapping[str, Any], key: Any, expected: Any) -> bool:
    if not isinstance(key, str):
        return False
    field_name, _, modifier = key.partition("|")
    actual = _event_value(event, field_name)
    if modifier == "exists":
        return actual is not None
    if field_name == "EventID":
        values = expected if isinstance(expected, list) else [expected]
        return actual in values
    return actual == expected


def _event_value(event: Mapping[str, Any], field_name: str) -> Any:
    if field_name in event:
        return event[field_name]
    current: Any = event
    for part in field_name.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def _coerce_evidence(
    value: SigmaEvidence | Mapping[str, Any] | Iterable[Any] | Any | None,
) -> SigmaEvidence:
    if value is None:
        return SigmaEvidence()
    if isinstance(value, SigmaEvidence):
        return value
    if isinstance(value, SigmaEvidenceRecord):
        return SigmaEvidence(provenance=(value,))
    if not isinstance(value, (str, bytes, Mapping)) and hasattr(value, "source_id"):
        return _coerce_evidence(
            {
                "source": getattr(value, "source", None),
                "source_id": getattr(value, "source_id", None),
                "rationale": getattr(value, "rationale", None),
                "confidence": getattr(value, "confidence", None),
                "url": getattr(value, "url", None),
                "cve_ids": getattr(value, "cve_ids", None),
                "cwe_ids": getattr(value, "cwe_ids", None),
                "capec_ids": getattr(value, "capec_ids", None),
            }
        )
    if (
        not isinstance(value, (str, bytes, Mapping))
        and isinstance(value, Iterable)
    ):
        merged = SigmaEvidence()
        for item in value:
            merged = _merge_evidence(merged, _coerce_evidence(item))
        return merged
    if not isinstance(value, Mapping):
        raise TypeError("evidence must be SigmaEvidence, a mapping, iterable, or None")

    def values(*names: str) -> tuple[str, ...]:
        for name in names:
            if name in value:
                raw = value[name]
                if raw is None:
                    return ()
                if isinstance(raw, str):
                    return (raw,)
                if isinstance(raw, Iterable):
                    return tuple(
                        str(item)
                        for item in raw
                        if item is not None and (not isinstance(item, str) or item)
                    )
                raise TypeError(f"evidence field {name!r} must be a string or iterable")
        return ()

    source_id = _optional_string(value.get("source_id"))
    cve_ids = values("cve_ids", "cves", "cve", "cve_id")
    cwe_ids = values("cwe_ids", "cwes", "cwe", "cwe_id")
    capec_ids = values("capec_ids", "capecs", "capec", "capec_id")
    if source_id and source_id.upper().startswith("CVE-") and not cve_ids:
        cve_ids = (source_id,)
    if source_id and source_id.upper().startswith("CWE-") and not cwe_ids:
        cwe_ids = (source_id,)
    if source_id and source_id.upper().startswith("CAPEC-") and not capec_ids:
        capec_ids = (source_id,)
    return SigmaEvidence(
        cve_ids=cve_ids,
        cwe_ids=cwe_ids,
        capec_ids=capec_ids,
        references=values("references", "urls", "url"),
        notes=values("notes", "rationale"),
        source=_optional_string(value.get("source")),
        source_id=_optional_string(value.get("source_id")),
        rationale=_optional_string(value.get("rationale")),
        confidence=_optional_string(value.get("confidence")),
        url=_optional_string(value.get("url")),
    )


def _merge_evidence(first: SigmaEvidence, second: SigmaEvidence) -> SigmaEvidence:
    provenance = (*first.provenance, *second.provenance)
    return SigmaEvidence(
        cve_ids=_unique((*first.cve_ids, *second.cve_ids)),
        cwe_ids=_unique((*first.cwe_ids, *second.cwe_ids)),
        capec_ids=_unique((*first.capec_ids, *second.capec_ids)),
        references=_unique((*first.references, *second.references)),
        notes=_unique((*first.notes, *second.notes)),
        source=first.source or second.source,
        source_id=first.source_id or second.source_id,
        rationale=first.rationale or second.rationale,
        confidence=first.confidence or second.confidence,
        url=first.url or second.url,
        provenance=provenance,
    )


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError("evidence metadata values must be strings")
    return value or None


def _normalize_fields(fields: Iterable[Any]) -> tuple[str, ...]:
    normalized: list[str] = []
    for field_name in fields:
        if not isinstance(field_name, str):
            raise ValueError("Detection field names must be strings")
        field_name = field_name.strip()
        if not field_name:
            raise ValueError("Detection field names must not be empty")
        if "|" in field_name:
            raise ValueError(
                f"Detection field {field_name!r} must not contain a Sigma modifier"
            )
        normalized.append(field_name)
    return _unique(tuple(normalized))


def _normalize_logsource(logsource: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(logsource, Mapping):
        raise ValueError("Sigma logsource override must be a mapping")
    normalized: dict[str, str] = {}
    for key, value in logsource.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError("Sigma logsource keys must be non-empty strings")
        if not isinstance(value, str) or not value.strip():
            raise ValueError("Sigma logsource values must be non-empty strings")
        normalized[key.strip()] = value.strip()
    if not any(key in normalized for key in ("category", "product", "service")):
        raise ValueError("Sigma logsource needs category, product, or service")
    return normalized


def _logsource_for(requirement: DetectionRequirement) -> dict[str, str] | None:
    names = [component.name for component in requirement.data_components]
    names.extend(
        source
        for component in requirement.data_components
        for source in component.log_sources
    )
    lowered = [
        re.sub(r"\s+", " ", name.strip()).casefold()
        for name in names
        if isinstance(name, str) and name.strip()
    ]
    for name in lowered:
        if name in _LOGSOURCE_MAP:
            return dict(_LOGSOURCE_MAP[name])
    return None


def _description_for(requirement: DetectionRequirement, ambiguous_events: list[str]) -> str:
    descriptions = tuple(
        analytic.description.strip()
        for analytic in requirement.analytics
        if analytic.description.strip()
    )
    text = " ".join(dict.fromkeys(descriptions))
    warnings = [
        "Generated from ATT&CK telemetry requirements; suspicious values were not specified.",
    ]
    if ambiguous_events:
        warnings.append(
            "Unparsed event labels were retained in provenance and were not used as detection."
        )
    return " ".join(part for part in (text, *warnings) if part)
