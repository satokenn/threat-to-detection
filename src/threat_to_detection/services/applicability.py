"""Threat-model applicability and detection-feasibility evaluation.

The evaluator deliberately keeps attack applicability independent from
telemetry coverage.  A path can therefore be applicable while its detection
candidate is unavailable or only partially observable.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any, Literal

from threat_to_detection.models.system import Asset, Flow, SystemModel
from threat_to_detection.models.threat import ThreatApplicabilityProfile

ApplicabilityStatus = Literal["applicable", "blocked", "unknown"]
ConditionStatus = Literal["satisfied", "blocked", "unknown"]

_PRIVILEGE_RANKS = {
    "anonymous": 0,
    "guest": 0,
    "user": 1,
    "operator": 2,
    "service": 2,
    "admin": 3,
    "administrator": 3,
    "root": 4,
    "system": 4,
}


def evaluate_attack_applicability(
    system: SystemModel,
    *,
    asset: Asset,
    trace_id: str,
    profile: ThreatApplicabilityProfile | None = None,
) -> dict[str, Any]:
    """Evaluate explicit system conditions for one ATT&CK candidate.

    Existing pipeline traces use the scenario-level requirements.  A threat
    universe supplies a candidate-specific profile, including flow direction
    and prerequisites, so candidates are not all evaluated against the same
    asset-level condition set.
    """

    preconditions = _precondition_conditions(system, profile)
    if profile is not None and profile.flow_scope == "local":
        conditions = preconditions or (
            _condition(
                "reachability",
                "satisfied",
                "The candidate is local and does not require a network flow.",
                evidence=(),
                provenance=_provenance(
                    system,
                    f"asset:{asset.name}",
                    "local_access",
                    source_type="threat_candidate",
                    rationale=profile.rationale,
                ),
            ),
        )
        statuses = tuple(item["status"] for item in conditions)
        status: ApplicabilityStatus = (
            "blocked"
            if "blocked" in statuses
            else "unknown"
            if "unknown" in statuses
            else "applicable"
        )
        blocked_reasons = tuple(
            _reason_code(item["condition"]) for item in conditions if item["status"] == "blocked"
        )
        return _applicability_result(
            status,
            conditions,
            blocked_reasons=blocked_reasons,
            trace_id=trace_id,
            flow_evaluations=(),
        )

    flows = _candidate_flows(system, asset, profile)
    flow_evaluations = tuple(
        _evaluate_flow(system, asset, flow, trace_id, index, profile)
        for index, flow in enumerate(flows, start=1)
    )
    if not flow_evaluations:
        condition = _condition(
            "reachability",
            "blocked",
            "No explicit communication flow reaches the target asset.",
            evidence=(),
            provenance=_provenance(system, f"asset:{asset.name}", "flows"),
        )
        return _applicability_result(
            "blocked",
            (condition,),
            blocked_reasons=("communication_path",),
            trace_id=trace_id,
            flow_evaluations=(),
        )

    statuses = tuple(item["status"] for item in flow_evaluations)
    flow_status = _aggregate_flow_status(statuses)
    precondition_statuses = tuple(item["status"] for item in preconditions)
    if "blocked" in precondition_statuses or flow_status == "blocked":
        status: ApplicabilityStatus = "blocked"
    elif "unknown" in precondition_statuses or flow_status == "unknown":
        status = "unknown"
    else:
        status = "applicable"
    conditions = tuple(
        condition for condition in preconditions
    ) + tuple(
        condition
        for item in flow_evaluations
        for condition in item["evaluated_conditions"]
    )
    blocked_reasons = tuple(
        dict.fromkeys(
            reason
            for item in flow_evaluations
            for reason in item["blocked_reasons"]
        )
    )
    unknown_reasons = tuple(
        dict.fromkeys(
            reason
            for item in flow_evaluations
            for reason in item["unknown_reasons"]
        )
    )
    unknown_reasons = tuple(
        dict.fromkeys(
            (*unknown_reasons, *(_reason_code(item["condition"])
                                 for item in preconditions
                                 if item["status"] == "unknown"))
        )
    )
    blocked_reasons = tuple(
        dict.fromkeys(
            (*blocked_reasons, *(_reason_code(item["condition"])
                                 for item in preconditions
                                 if item["status"] == "blocked"))
        )
    )
    result_blocked_reasons = blocked_reasons if status == "blocked" else ()
    result_unknown_reasons = unknown_reasons if status == "unknown" else ()
    evidence = tuple(
        evidence
        for item in flow_evaluations
        for evidence in item["evidence"]
    )
    provenance = tuple(
        provenance
        for item in flow_evaluations
        for provenance in item["provenance"]
    )
    reasons = _reason_text(status, result_blocked_reasons, result_unknown_reasons)
    return {
        "status": status,
        "reasons": list(reasons),
        "evidence": list(evidence),
        "evaluated_conditions": list(conditions),
        "provenance": list(provenance),
        "blocked_reason": result_blocked_reasons[0] if result_blocked_reasons else None,
        "blocked_reasons": list(result_blocked_reasons),
        "unknown_reason": result_unknown_reasons[0] if result_unknown_reasons else None,
        "unknown_reasons": list(result_unknown_reasons),
        "trace_id": trace_id,
        "flow_evaluations": list(flow_evaluations),
    }


def _aggregate_flow_status(statuses: tuple[str, ...]) -> ApplicabilityStatus:
    """Aggregate alternative flows before applying candidate-common conditions."""

    if "applicable" in statuses:
        return "applicable"
    if statuses and all(value == "blocked" for value in statuses):
        return "blocked"
    return "unknown"


def evaluate_detection_feasibility(
    coverage: dict[str, Any],
    *,
    asset: Asset,
    trace_id: str,
    has_detection_requirement: bool,
) -> dict[str, Any]:
    """Turn existing event/field coverage into the Issue #24 output shape."""

    if not has_detection_requirement:
        return {
            "status": "unknown",
            "reasons": ["No detection requirement or required telemetry is declared."],
            "evidence": [],
            "evaluated_conditions": [
                {"condition": "required_telemetry", "status": "unknown"},
                {"condition": "required_fields", "status": "unknown"},
                {"condition": "authentication_logs", "status": "unknown"},
                {"condition": "asset_logs", "status": "unknown"},
            ],
            "provenance": [
                _provenance(
                    None,
                    f"trace:{trace_id}",
                    "detection_requirement",
                    source_type="derived",
                    rationale="No detection requirement was available for this ATT&CK candidate.",
                )
            ],
        }

    missing_events = tuple(coverage.get("missing_events", ()))
    missing_fields = tuple(coverage.get("missing_fields", ()))
    required_auth = tuple(coverage.get("required_authentication_logs", ()))
    available_events = {
        _telemetry_key(value) for value in coverage.get("available_events", ())
    }
    missing_auth = tuple(
        value for value in required_auth if _telemetry_key(value) not in available_events
    )
    required_events = tuple(coverage.get("required_events", ()))
    event_status = _coverage_condition(required_events, missing_events)
    field_status = _coverage_condition(
        tuple(coverage.get("required_fields", ())), missing_fields
    )
    auth_status = _coverage_condition(required_auth, missing_auth)
    logs_status: str = "available" if asset.logs else "unknown"
    coverage_status = str(coverage.get("status"))
    if coverage_status == "unavailable":
        status = "unavailable"
    elif coverage_status == "partial":
        status = "partial"
    elif any(value == "missing" for value in (event_status, field_status, auth_status)):
        status = "partial"
    elif any(
        value == "unknown"
        for value in (event_status, field_status, auth_status, logs_status)
    ):
        status = "unknown"
    else:
        status = "detectable"
    reasons = []
    if missing_events:
        reasons.append(f"Required telemetry is missing: {', '.join(missing_events)}.")
    if missing_fields:
        reasons.append(f"Required fields are missing: {', '.join(missing_fields)}.")
    if missing_auth:
        reasons.append(f"Required authentication logs are missing: {', '.join(missing_auth)}.")
    if logs_status == "unknown":
        reasons.append("Asset log availability is not declared.")
    if not reasons:
        reasons.append("All declared detection inputs are available.")
    evidence = [
        {"kind": "coverage", "field": "coverage_ratio", "value": coverage.get("coverage_ratio")},
        {"kind": "asset", "id": asset.name, "field": "logs", "value": list(asset.logs)},
    ]
    return {
        "status": status,
        "reasons": reasons,
        "evidence": evidence,
        "evaluated_conditions": [
            {"condition": "required_telemetry", "status": event_status},
            {"condition": "required_fields", "status": field_status},
            {"condition": "authentication_logs", "status": auth_status},
            {"condition": "asset_logs", "status": logs_status},
        ],
        "provenance": [
            {
                "source_type": "system_model",
                "source_id": f"asset:{asset.name}",
                "field": "logs",
                "rationale": "Declared logs are used as the availability evidence.",
            },
            {
                "source_type": "derived",
                "source_id": f"trace:{trace_id}",
                "field": "coverage",
                "rationale": (
                    "Event and field statuses are derived from required and available telemetry."
                ),
            },
        ],
    }


def _evaluate_flow(
    system: SystemModel,
    asset: Asset,
    flow: Flow,
    trace_id: str,
    index: int,
    profile: ThreatApplicabilityProfile | None = None,
) -> dict[str, Any]:
    conditions: list[dict[str, Any]] = []
    blocked_reasons: list[str] = []
    unknown_reasons: list[str] = []
    evidence: list[dict[str, Any]] = []
    provenance: list[dict[str, Any]] = []

    _append_condition(
        conditions,
        blocked_reasons,
        unknown_reasons,
        _condition(
            "reachability",
            "satisfied",
            (
                "An explicit flow matches the candidate's flow requirements."
                if profile is not None
                else "An explicit flow reaches the target asset."
            ),
            evidence=_flow_evidence(
                flow,
                "source"
                if profile is not None and profile.flow_direction == "outbound"
                else "destination",
            ),
            provenance=_provenance(system, f"flow:{flow.source}->{flow.destination}", "flows"),
        ),
    )
    _append_condition(
        conditions,
        blocked_reasons,
        unknown_reasons,
        _condition(
            "trust_boundary",
            _trust_boundary_status(system, flow, profile),
            _trust_boundary_reason(system, flow, profile),
            evidence=_flow_evidence(flow, "trust_boundary"),
            provenance=_provenance(
                system,
                f"flow:{flow.source}->{flow.destination}",
                "trust_boundary",
            ),
        ),
    )
    auth_status, auth_reason = _access_status(
        flow.authentication,
        "authentication",
        required=(
            profile.authentication_required
            if profile is not None and profile.authentication_required is not None
            else None
        ),
        candidate_requirement_declared=(
            profile is None or profile.authentication_required is not None
        ),
    )
    _append_condition(
        conditions,
        blocked_reasons,
        unknown_reasons,
        _condition(
            "authentication",
            auth_status,
            auth_reason,
            evidence=_flow_evidence(flow, "authentication"),
            provenance=_provenance(
                system,
                f"flow:{flow.source}->{flow.destination}",
                "authentication",
            ),
        ),
    )
    authz_status, authz_reason = _access_status(
        flow.authorization,
        "authorization",
        required=(
            profile.authorization_required
            if profile is not None and profile.authorization_required is not None
            else None
        ),
        candidate_requirement_declared=(
            profile is None or profile.authorization_required is not None
        ),
    )
    _append_condition(
        conditions,
        blocked_reasons,
        unknown_reasons,
        _condition(
            "authorization",
            authz_status,
            authz_reason,
            evidence=_flow_evidence(flow, "authorization"),
            provenance=_provenance(
                system,
                f"flow:{flow.source}->{flow.destination}",
                "authorization",
            ),
        ),
    )
    privilege_status, privilege_reason = _privilege_status(system, asset, flow, profile)
    _append_condition(
        conditions,
        blocked_reasons,
        unknown_reasons,
        _condition(
            "privilege",
            privilege_status,
            privilege_reason,
            evidence=_asset_evidence(asset, "privilege_level"),
            provenance=(
                _provenance(system, f"asset:{asset.name}", "privilege_level"),
                _provenance(
                    system,
                    f"scenario:{system.metadata.get('name', 'scenario')}",
                    "required_privilege",
                    source_type="scenario_author",
                    rationale=(
                        "The required privilege is explicitly declared by the evaluation scenario."
                    ),
                ),
            ),
        ),
    )
    transition_status, transition_reason = _transition_status(system, asset, flow)
    _append_condition(
        conditions,
        blocked_reasons,
        unknown_reasons,
        _condition(
            "privilege_transition",
            transition_status,
            transition_reason,
            evidence=_asset_evidence(asset, "privilege_transition"),
            provenance=(
                _provenance(
                    system,
                    f"scenario:{system.metadata.get('name', 'scenario')}",
                    "privilege_transition",
                    source_type="scenario_author",
                    rationale=(
                        "The required privilege transition is explicitly declared "
                        "by the evaluation scenario."
                    ),
                ),
                _provenance(
                    system,
                    f"trace:{trace_id}",
                    "privilege_transition",
                    source_type="derived",
                ),
            ),
        ),
    )
    statuses = tuple(item["status"] for item in conditions)
    status: ApplicabilityStatus = (
        "blocked" if "blocked" in statuses else "unknown" if "unknown" in statuses else "applicable"
    )
    for item in conditions:
        evidence.extend(item["evidence"])
        provenance.extend(item["provenance"])
    return {
        "flow_id": f"flow-{index}:{flow.source}->{flow.destination}",
        "from": flow.source,
        "to": flow.destination,
        "status": status,
        "reasons": _reason_text(status, tuple(blocked_reasons), tuple(unknown_reasons)),
        "evidence": evidence,
        "evaluated_conditions": conditions,
        "provenance": provenance,
        "blocked_reasons": list(dict.fromkeys(blocked_reasons)),
        "unknown_reasons": list(dict.fromkeys(unknown_reasons)),
    }


def _access_status(
    condition: Any,
    label: str,
    *,
    required: bool | None = None,
    candidate_requirement_declared: bool = True,
) -> tuple[ConditionStatus, str]:
    if not candidate_requirement_declared:
        return "unknown", f"Whether the candidate requires {label} is not declared."
    if required is False:
        return "satisfied", f"The candidate does not require {label}."
    if required is True:
        if condition is None:
            return "unknown", f"The candidate requires {label}, but the condition is not declared."
        if condition.satisfied is False or condition.required is False:
            return "blocked", f"The explicit {label} condition does not satisfy the candidate."
        if condition.satisfied is True:
            return "satisfied", f"The candidate's {label} prerequisite is satisfied."
        return "unknown", f"The candidate's {label} prerequisite cannot be determined."
    if condition is None:
        return "unknown", f"{label.capitalize()} condition is not declared."
    if condition.satisfied is False:
        return "blocked", f"The explicit {label} condition is not satisfied."
    if condition.required is False:
        return "satisfied", f"{label.capitalize()} is explicitly not required."
    if condition.satisfied is True:
        return "satisfied", f"The explicit {label} condition is satisfied."
    return "unknown", f"The required {label} condition cannot be determined."


def _trust_boundary_status(
    system: SystemModel,
    flow: Flow,
    profile: ThreatApplicabilityProfile | None = None,
) -> ConditionStatus:
    if profile is not None:
        if profile.trust_boundary_required is False:
            return "satisfied"
        if profile.trust_boundary_required is None:
            return "unknown"
        required = profile.required_trust_boundary
        if required is None:
            return "unknown"
    else:
        required = system.scenario.required_trust_boundary
    if flow.trust_boundary is None:
        return "unknown"
    if required is not None and flow.trust_boundary != required:
        return "blocked"
    return "satisfied"


def _trust_boundary_reason(
    system: SystemModel,
    flow: Flow,
    profile: ThreatApplicabilityProfile | None = None,
) -> str:
    if profile is not None and profile.trust_boundary_required is False:
        return "The candidate does not require a declared trust boundary."
    if profile is not None and profile.trust_boundary_required is None:
        return "Whether the candidate requires a trust boundary is not declared."
    required = (
        profile.required_trust_boundary
        if profile is not None
        else system.scenario.required_trust_boundary
    )
    if profile is not None and required is None:
        return "The candidate's required trust boundary is not declared."
    if flow.trust_boundary is None:
        return "Trust boundary is not declared."
    if required is not None and flow.trust_boundary != required:
        return "The declared trust boundary does not satisfy the required boundary."
    return "The trust boundary is explicitly declared."


def _privilege_status(
    system: SystemModel,
    asset: Asset,
    flow: Flow,
    profile: ThreatApplicabilityProfile | None = None,
) -> tuple[ConditionStatus, str]:
    if profile is not None:
        if profile.privilege_required is False:
            return "satisfied", "The candidate does not require a privilege level."
        if profile.privilege_required is True:
            required = profile.required_privilege
            if required is None:
                return "unknown", "The candidate's required privilege is not declared."
        else:
            return "unknown", "Whether the candidate requires privilege is not declared."
    else:
        required = system.scenario.required_privilege
    if required is None:
        return "unknown", "Required privilege is not declared."
    if asset.privilege_level is None:
        return "unknown", "Target privilege level is not declared."
    comparison = _compare_privileges(asset.privilege_level, required)
    if comparison is None:
        return "unknown", "Privilege levels are not comparable from the declared values."
    if comparison < 0:
        return "blocked", "Target asset privilege is below the required privilege."
    return "satisfied", "Target asset privilege meets the required privilege."


def _transition_status(
    system: SystemModel, asset: Asset, flow: Flow
) -> tuple[ConditionStatus, str]:
    transition = system.scenario.privilege_transition
    if transition is None:
        return "satisfied", "No privilege transition is required by the scenario."
    parts = tuple(part.strip() for part in re.split(r"\s*(?:->|to)\s*", transition, flags=re.I))
    if len(parts) != 2 or not all(parts):
        return "unknown", "Privilege transition format is not comparable."
    source = next((item for item in system.assets if item.name == flow.source), None)
    if source is None or source.privilege_level is None or asset.privilege_level is None:
        return (
            "unknown",
            "Source and target privilege levels are required to evaluate the transition.",
        )
    source_comparison = _compare_privileges(source.privilege_level, parts[0])
    target_comparison = _compare_privileges(asset.privilege_level, parts[1])
    if source_comparison is None or target_comparison is None:
        return "unknown", "Privilege transition levels are not comparable."
    if source_comparison < 0 or target_comparison < 0:
        return "blocked", "The explicit privilege transition cannot be satisfied."
    return "satisfied", "The explicit privilege transition is supported by the model."


def _compare_privileges(actual: str, required: str) -> int | None:
    actual_key = actual.strip().casefold()
    required_key = required.strip().casefold()
    if actual_key not in _PRIVILEGE_RANKS or required_key not in _PRIVILEGE_RANKS:
        return 0 if actual_key == required_key else None
    return _PRIVILEGE_RANKS[actual_key] - _PRIVILEGE_RANKS[required_key]


def _applicability_result(
    status: ApplicabilityStatus,
    conditions: Iterable[dict[str, Any]],
    *,
    blocked_reasons: tuple[str, ...],
    trace_id: str,
    flow_evaluations: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    conditions = tuple(conditions)
    unknown_reasons = tuple(
        condition["condition"]
        for condition in conditions
        if condition["status"] == "unknown"
    )
    evidence = tuple(
        evidence_item
        for condition in conditions
        for evidence_item in condition["evidence"]
    )
    provenance = tuple(
        provenance_item
        for condition in conditions
        for provenance_item in condition["provenance"]
    )
    return {
        "status": status,
        "reasons": _reason_text(status, blocked_reasons, unknown_reasons),
        "evidence": list(evidence),
        "evaluated_conditions": list(conditions),
        "provenance": list(provenance),
        "blocked_reason": blocked_reasons[0] if blocked_reasons else None,
        "blocked_reasons": list(blocked_reasons),
        "unknown_reason": unknown_reasons[0] if unknown_reasons else None,
        "unknown_reasons": list(unknown_reasons),
        "trace_id": trace_id,
        "flow_evaluations": list(flow_evaluations),
    }


def _append_condition(
    conditions: list[dict[str, Any]],
    blocked_reasons: list[str],
    unknown_reasons: list[str],
    condition: dict[str, Any],
) -> None:
    conditions.append(condition)
    if condition["status"] == "blocked":
        blocked_reasons.append(_reason_code(condition["condition"]))
    elif condition["status"] == "unknown":
        unknown_reasons.append(_reason_code(condition["condition"]))


def _condition(
    name: str,
    status: ConditionStatus,
    reason: str,
    *,
    evidence: Iterable[dict[str, Any]],
    provenance: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    if isinstance(evidence, dict):
        evidence = (evidence,)
    if isinstance(provenance, dict):
        provenance = (provenance,)
    return {
        "condition": name,
        "status": status,
        "reason": reason,
        "evidence": list(evidence),
        "provenance": list(provenance),
    }


def _coverage_condition(required: tuple[str, ...], missing: tuple[str, ...]) -> str:
    if not required:
        return "available"
    if missing and len(missing) == len(required):
        return "missing"
    if missing:
        return "missing"
    return "available"


def _reason_code(condition: str) -> str:
    return {
        "reachability": "communication_path",
        "trust_boundary": "trust_boundary",
        "authentication": "authentication",
        "authorization": "authorization",
        "privilege": "privilege",
        "privilege_transition": "privilege_transition",
        "preconditions": "preconditions",
    }[condition]


def _reason_text(
    status: ApplicabilityStatus,
    blocked_reasons: tuple[str, ...],
    unknown_reasons: tuple[str, ...],
) -> list[str]:
    if status == "blocked":
        return [f"Blocked by: {', '.join(blocked_reasons)}."]
    if status == "unknown":
        return [f"Unknown because: {', '.join(unknown_reasons)}."]
    return ["All required attack applicability conditions are satisfied."]


def _candidate_flows(
    system: SystemModel,
    asset: Asset,
    profile: ThreatApplicabilityProfile | None,
) -> tuple[Flow, ...]:
    if profile is None or profile.flow_direction == "inbound":
        flows = tuple(flow for flow in system.flows if flow.destination == asset.name)
    elif profile.flow_direction == "outbound":
        flows = tuple(flow for flow in system.flows if flow.source == asset.name)
    else:
        flows = tuple(
            flow
            for flow in system.flows
            if flow.source == asset.name or flow.destination == asset.name
        )
    if profile is not None and profile.flow_source is not None:
        flows = tuple(flow for flow in flows if flow.source == profile.flow_source)
    if profile is not None and profile.flow_destination is not None:
        flows = tuple(flow for flow in flows if flow.destination == profile.flow_destination)
    if profile is not None and profile.protocol is not None:
        protocol = profile.protocol.casefold()
        flows = tuple(
            flow for flow in flows if flow.protocol and flow.protocol.casefold() == protocol
        )
    return flows


def _precondition_conditions(
    system: SystemModel,
    profile: ThreatApplicabilityProfile | None,
) -> tuple[dict[str, Any], ...]:
    if profile is None or not profile.required_preconditions:
        return ()
    available = set(system.preconditions)
    missing = tuple(value for value in profile.required_preconditions if value not in available)
    if missing:
        return (
            _condition(
                "preconditions",
                "unknown",
                f"Required preconditions are not declared: {', '.join(missing)}.",
                evidence=(),
                provenance=_provenance(
                    system,
                    f"scenario:{system.metadata.get('name', 'scenario')}",
                    "preconditions",
                    source_type="system_model",
                    rationale="The target system does not declare all candidate preconditions.",
                ),
            ),
        )
    return (
        _condition(
            "preconditions",
            "satisfied",
            "All candidate preconditions are declared by the target system.",
            evidence=(),
            provenance=_provenance(
                system,
                f"scenario:{system.metadata.get('name', 'scenario')}",
                "preconditions",
                source_type="system_model",
            ),
        ),
    )


def _provenance(
    system: SystemModel | None,
    source_id: str,
    field: str,
    *,
    source_type: str = "system_model",
    rationale: str | None = None,
) -> dict[str, str]:
    return {
        "source_type": source_type,
        "source_id": source_id,
        "field": field,
        "rationale": rationale
        or "The value is explicitly declared in the SystemModel.",
    }


def _flow_evidence(flow: Flow, field: str) -> tuple[dict[str, Any], ...]:
    value = getattr(flow, field)
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return (
        {
            "kind": "flow",
            "id": f"{flow.source}->{flow.destination}",
            "field": field,
            "value": value,
        },
    )


def _asset_evidence(asset: Asset, field: str) -> tuple[dict[str, Any], ...]:
    return (
        {
            "kind": "asset",
            "id": asset.name,
            "field": field,
            "value": getattr(asset, field, None),
        },
    )


def _telemetry_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")
