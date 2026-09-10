"""Independent attack-applicability and detection-feasibility analysis.

The two decisions in this module deliberately use different inputs.  Missing
telemetry can make a path hard to detect, but it never makes the attack path
inapplicable.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from threat_to_detection.models.detection import DetectionRequirement
from threat_to_detection.models.scenario import (
    AccessCondition,
    ScenarioContext,
    TelemetryRequirement,
)
from threat_to_detection.models.system import Asset, Flow, SystemModel


def provenance(source_type: str, source_id: str, field: str, rationale: str) -> dict[str, str]:
    return {
        "source_type": source_type,
        "source_id": source_id,
        "field": field,
        "rationale": rationale,
    }


def evaluate_attack_applicability(
    system: SystemModel,
    asset: Asset,
    context: ScenarioContext,
    *,
    trace_id: str,
) -> dict[str, Any]:
    """Evaluate all candidate incoming flows for one TracePath.

    A candidate is applicable when every condition on that candidate is
    satisfied.  Candidate aggregation is intentionally three-valued and
    keeps the individual flow evaluations in the output.
    """

    candidates = [
        (index, flow)
        for index, flow in enumerate(system.flows, start=1)
        if flow.destination == asset.name
    ]
    if not candidates:
        blocked = _condition(
            "reachability",
            "blocked",
            "no explicit Flow reaches the target Asset",
            evidence=(
                _evidence(
                    "asset",
                    asset.name,
                    "flows",
                    (),
                    provenance(
                        "system_model",
                        f"asset:{asset.name}",
                        "flows",
                        "SystemModelに対象Assetへ到達するFlowがない",
                    ),
                ),
            ),
        )
        return _applicability_result(
            "blocked",
            "no explicit Flow reaches the target Asset",
            (blocked,),
            (),
            trace_id,
        )

    flow_results: list[dict[str, Any]] = []
    for index, flow in candidates:
        flow_id = _flow_id(flow, index)
        conditions = _evaluate_flow(system, asset, context, flow, flow_id)
        statuses = [item["status"] for item in conditions]
        status = (
            "blocked"
            if "blocked" in statuses
            else "unknown"
            if "unknown" in statuses
            else "applicable"
        )
        reasons = [item["reason"] for item in conditions if item["status"] != "satisfied"]
        flow_results.append(
            {
                "flow_id": flow_id,
                "from": flow.source,
                "to": flow.destination,
                "protocol": flow.protocol,
                "status": status,
                "reasons": reasons,
                "evaluated_conditions": conditions,
                "evidence": [evidence for item in conditions for evidence in item["evidence"]],
                "provenance": [
                    evidence["provenance"] for item in conditions for evidence in item["evidence"]
                ],
            }
        )

    if any(item["status"] == "applicable" for item in flow_results):
        status = "applicable"
    elif all(item["status"] == "blocked" for item in flow_results):
        status = "blocked"
    else:
        status = "unknown"
    reasons = [
        f"{item['flow_id']}: {reason}" for item in flow_results for reason in item["reasons"]
    ]
    conditions = _aggregate_conditions(flow_results)
    evidence = [evidence for item in flow_results for evidence in item["evidence"]]
    source_provenance = [item["provenance"] for item in evidence]
    source_provenance.append(
        provenance(
            "derived",
            trace_id,
            "attack_applicability.status",
            "candidate Flowの状態を blocked > unknown > applicable の規則で集約した",
        )
    )
    return {
        "status": status,
        "reasons": reasons or ["all applicability conditions are satisfied"],
        "evidence": evidence,
        "evaluated_conditions": conditions,
        "provenance": source_provenance,
        "candidate_flows": flow_results,
    }


def evaluate_detection_feasibility(
    system: SystemModel,
    asset: Asset,
    context: ScenarioContext,
    requirement: DetectionRequirement | None,
    *,
    trace_id: str,
) -> dict[str, Any]:
    """Evaluate telemetry independently from attack applicability."""

    required = _required_specs(context, requirement)
    available, availability_declared = _available_specs(context, asset)
    available_by_key = {_telemetry_key(item.event_type): item for item in available}
    authentication_events = {_telemetry_key(item) for item in context.required_authentication_logs}

    event_states: list[tuple[str, str, str]] = []
    field_states: list[tuple[str, str, str]] = []
    for spec in required:
        key = _telemetry_key(spec.event_type)
        if key in available_by_key:
            event_status = "available"
        elif availability_declared:
            event_status = "missing"
        else:
            event_status = "unknown"
        event_states.append((spec.event_type, event_status, key))
        available_spec = available_by_key.get(key)
        for field in spec.fields:
            if available_spec is None:
                field_status = event_status
            elif _field_key(field) in {_field_key(value) for value in available_spec.fields}:
                field_status = "available"
            elif _context_fields(context, spec.event_type) is not None:
                field_status = "missing"
            else:
                field_status = "unknown"
            field_states.append((f"{spec.event_type}.{field}", field_status, key))

    telemetry_status = _aggregate_condition_status(
        [status for _name, status, _key in event_states], default="unknown"
    )
    fields_status = _aggregate_condition_status(
        [status for _name, status, _key in field_states], default=telemetry_status
    )
    auth_states = [
        status
        for name, status, _key in event_states
        if _telemetry_key(name) in authentication_events
    ]
    auth_status = _aggregate_condition_status(auth_states, default="available")
    logsource_status = _logsource_status(asset, required)

    condition_data = (
        ("required_telemetry", telemetry_status, event_states),
        ("required_fields", fields_status, field_states),
        (
            "authentication_logs",
            auth_status,
            [
                (name, status, _telemetry_key(name))
                for name, status, _key in event_states
                if _telemetry_key(name) in authentication_events
            ],
        ),
        ("asset_logsource", logsource_status, []),
    )
    conditions = []
    evidence: list[dict[str, Any]] = []
    for condition_name, status, items in condition_data:
        item_evidence = []
        for name, item_status, _key in items:
            item_evidence.append(
                _telemetry_evidence(
                    condition_name, name, item_status, context, asset, requirement
                )
            )
            item_evidence.extend(
                _availability_evidence(condition_name, name, item_status, context, asset)
            )
        if not item_evidence:
            item_evidence = [
                _telemetry_evidence(
                    condition_name, condition_name, status, context, asset, requirement
                )
            ]
            item_evidence.extend(
                _availability_evidence(condition_name, condition_name, status, context, asset)
            )
        conditions.append(
            {
                "condition": condition_name,
                "status": status,
                "evidence": item_evidence,
            }
        )
        evidence.extend(item_evidence)

    statuses = [item["status"] for item in conditions]
    if not required:
        status = "unknown"
        reasons = ["no required telemetry is available for this path"]
    elif "missing" in statuses:
        known_available = sum(
            1 for item in (*event_states, *field_states) if item[1] == "available"
        )
        status = "partial" if known_available else "unavailable"
        reasons = [
            f"{item['condition']} has missing collection coverage"
            for item in conditions
            if item["status"] == "missing"
        ]
    elif "unknown" in statuses:
        status = "unknown"
        reasons = [
            f"{item['condition']} collection status is not specified"
            for item in conditions
            if item["status"] == "unknown"
        ]
    else:
        status = "detectable"
        reasons = ["all required telemetry and fields are available"]

    result_provenance = [item["provenance"] for item in evidence]
    result_provenance.append(
        provenance(
            "derived",
            trace_id,
            "detection_feasibility.status",
            "required telemetry, fields, authentication logs, and logsource conditionsを集約した",
        )
    )
    return {
        "status": status,
        "reasons": reasons,
        "evidence": evidence,
        "evaluated_conditions": [
            {
                "condition": item["condition"],
                "status": item["status"],
            }
            for item in conditions
        ],
        "provenance": result_provenance,
    }


def _evaluate_flow(
    system: SystemModel,
    target: Asset,
    context: ScenarioContext,
    flow: Flow,
    flow_id: str,
) -> tuple[dict[str, Any], ...]:
    source = next((asset for asset in system.assets if asset.name == flow.source), None)
    reachability_status = "satisfied" if source or flow.source in target.exposed_to else "unknown"
    reachability_evidence = [
        _evidence(
            "flow",
            flow_id,
            "from",
            flow.source,
            provenance(
                "system_model",
                f"flow:{flow_id}",
                "from",
                "SystemModelに明示されたFlowの送信元",
            ),
        )
    ]
    if source is None:
        reachability_evidence.append(
            _evidence(
                "asset",
                target.name,
                "exposed_to",
                list(target.exposed_to),
                provenance(
                    "system_model",
                    f"asset:{target.name}",
                    "exposed_to",
                    "外部送信元を対象Assetが明示的に受け入れる範囲",
                ),
            )
        )
    conditions = [
        _condition(
            "reachability",
            reachability_status,
            "explicit incoming Flow exists"
            if reachability_status == "satisfied"
            else "Flow source is not mapped to an Asset or exposed endpoint",
            evidence=tuple(reachability_evidence),
        ),
        _trust_condition(system, target, source, context, flow, flow_id),
        _access_condition("authentication", context.authentication, flow.authentication, flow_id),
        _access_condition("authorization", context.authorization, flow.authorization, flow_id),
        _privilege_condition(target, source, context, flow_id),
    ]
    return tuple(conditions)


def _trust_condition(
    system: SystemModel,
    target: Asset,
    source: Asset | None,
    context: ScenarioContext,
    flow: Flow,
    flow_id: str,
) -> dict[str, Any]:
    if context.required_trust_boundary:
        if flow.trust_boundary is None:
            status, reason = "unknown", "required trust boundary is not declared on the Flow"
        elif _same(flow.trust_boundary, context.required_trust_boundary):
            status, reason = "satisfied", "declared trust boundary matches the scenario"
        else:
            status, reason = "blocked", "declared trust boundary conflicts with the scenario"
    elif flow.trust_boundary:
        status, reason = "satisfied", "Flow declares the required trust-boundary crossing"
    elif (
        source
        and source.trust_zone
        and target.trust_zone
        and _same(source.trust_zone, target.trust_zone)
    ):
        status, reason = "satisfied", "source and target are explicitly in the same trust zone"
    else:
        status, reason = "unknown", "trust-boundary requirement cannot be determined"
    evidence = [
        _evidence(
            "flow",
            flow_id,
            "trust_boundary",
            flow.trust_boundary,
            provenance(
                "system_model",
                f"flow:{flow_id}",
                "trust_boundary",
                "SystemModelに明示された信頼境界",
            ),
        )
    ]
    if source is not None:
        evidence.append(
            _evidence(
                "asset",
                source.name,
                "trust_zone",
                source.trust_zone,
                provenance(
                    "system_model",
                    f"asset:{source.name}",
                    "trust_zone",
                    "Flow送信元Assetの信頼ゾーン",
                ),
            )
        )
    evidence.append(
        _evidence(
            "asset",
            target.name,
            "trust_zone",
            target.trust_zone,
            provenance(
                "system_model",
                f"asset:{target.name}",
                "trust_zone",
                "Flow送信先Assetの信頼ゾーン",
            ),
        )
    )
    if context.required_trust_boundary:
        evidence.append(
            _evidence(
                "scenario",
                f"trace:{flow_id}",
                "required_trust_boundary",
                context.required_trust_boundary,
                provenance(
                    "scenario_author",
                    f"scenario:{flow_id}",
                    "required_trust_boundary",
                    "シナリオ作成者が明示した必要な信頼境界",
                ),
            )
        )
    return _condition(
        "trust_boundary",
        status,
        reason,
        evidence=tuple(evidence),
    )


def _access_condition(
    name: str,
    scenario: AccessCondition | None,
    flow: Any,
    flow_id: str,
) -> dict[str, Any]:
    if scenario is None:
        if flow is None:
            status, reason = "unknown", f"{name} condition is not specified"
        elif flow.required is False:
            status, reason = "satisfied", f"Flow explicitly does not require {name}"
        else:
            status, reason = "unknown", f"Flow requires {name}, but satisfaction is not evidenced"
    elif scenario.satisfied is False:
        status, reason = "blocked", f"scenario explicitly marks {name} as unsatisfied"
    elif flow is None:
        status, reason = "unknown", f"Flow does not declare the scenario's {name} condition"
    elif scenario.required is False and flow.required is False:
        status, reason = "satisfied", f"scenario and Flow explicitly do not require {name}"
    elif scenario.required is False and flow.required is True:
        status, reason = (
            "blocked",
            f"Flow requires {name} although the scenario does not provide it",
        )
    elif flow.required is False and scenario.required is True:
        status, reason = "blocked", f"Flow explicitly disables the required {name} condition"
    elif scenario.satisfied is True and _access_fields_match(scenario, flow) == "matched":
        status, reason = "satisfied", f"scenario explicitly satisfies {name}"
    elif scenario.satisfied is True and _access_fields_match(scenario, flow) == "blocked":
        status, reason = "blocked", f"scenario {name} details conflict with the Flow"
    elif scenario.satisfied is True:
        status, reason = "unknown", f"scenario {name} details do not match the Flow"
    else:
        status, reason = "unknown", f"{name} satisfaction is not explicitly evidenced"
    evidence = []
    if flow is not None:
        evidence.append(
            _evidence(
                "flow",
                flow_id,
                f"{name}.required",
                getattr(flow, "required", None),
                provenance(
                    "system_model",
                    f"flow:{flow_id}",
                    f"{name}.required",
                    f"Flowに明示された{name}条件",
                ),
            )
        )
    if scenario is not None:
        evidence.append(
            _evidence(
                "scenario",
                f"trace:{flow_id}",
                name,
                scenario.model_dump(mode="json"),
                provenance(
                    "scenario_author",
                    f"scenario:{flow_id}",
                    name,
                    f"シナリオ作成者が明示した{name}条件",
                ),
            )
        )
    return _condition(
        name,
        status,
        reason,
        evidence=tuple(evidence),
    )


def _access_fields_match(scenario: AccessCondition, flow: Any) -> str:
    if flow.required is None:
        return "unknown"
    for field in ("method", "principal", "identity_source", "privilege"):
        expected = getattr(scenario, field)
        actual = getattr(flow, field, None)
        if expected is not None and actual is None:
            return "unknown"
        if expected is not None and not _same(expected, actual):
            return "blocked"
    for field in ("roles", "scopes"):
        expected = set(getattr(scenario, field))
        actual = set(getattr(flow, field, ()))
        if expected and not actual:
            return "unknown"
        if expected and not expected <= actual:
            return "blocked"
    return "matched"


def _privilege_condition(
    target: Asset,
    source: Asset | None,
    context: ScenarioContext,
    flow_id: str,
) -> dict[str, Any]:
    statuses: list[str] = []
    reasons: list[str] = []
    if context.required_privilege:
        if target.privilege_level is None:
            statuses.append("unknown")
            reasons.append("target privilege level is not specified")
        else:
            comparison = _compare_privilege(target.privilege_level, context.required_privilege)
            statuses.append(comparison)
            reasons.append(
                "target privilege satisfies the required privilege"
                if comparison == "satisfied"
                else "target privilege is below the required privilege"
            )
    if context.privilege_transition:
        transition = _parse_transition(context.privilege_transition)
        if (
            transition is None
            or source is None
            or source.privilege_level is None
            or target.privilege_level is None
        ):
            statuses.append("unknown")
            reasons.append("privilege transition cannot be compared with explicit asset levels")
        elif _same(transition[0], source.privilege_level) and _same(
            transition[1], target.privilege_level
        ):
            statuses.append("satisfied")
            reasons.append("declared privilege transition matches source and target")
        else:
            statuses.append("blocked")
            reasons.append("declared privilege transition does not match source and target")
    if not statuses:
        statuses.append("unknown")
        reasons.append("required privilege and privilege transition are not specified")
    status = (
        "blocked" if "blocked" in statuses else "unknown" if "unknown" in statuses else "satisfied"
    )
    return _condition(
        "privilege",
        status,
        "; ".join(reasons),
        evidence=(
            _evidence(
                "asset",
                target.name,
                "privilege_level",
                target.privilege_level,
                provenance(
                    "system_model",
                    f"asset:{target.name}",
                    "privilege_level",
                    "SystemModelに明示された対象Assetの権限レベル",
                ),
            ),
            _evidence(
                "scenario",
                f"trace:{flow_id}",
                "required_privilege",
                context.required_privilege,
                provenance(
                    "scenario_author",
                    f"scenario:{flow_id}",
                    "required_privilege",
                    "シナリオ作成者が明示した必要権限",
                ),
            ),
        ),
    )


def _applicability_result(
    status: str,
    reason: str,
    conditions: tuple[dict[str, Any], ...],
    candidates: tuple[dict[str, Any], ...],
    trace_id: str,
) -> dict[str, Any]:
    evidence = [evidence for item in conditions for evidence in item["evidence"]]
    return {
        "status": status,
        "reasons": [reason],
        "evidence": evidence,
        "evaluated_conditions": [
            {"condition": item["condition"], "status": item["status"]} for item in conditions
        ],
        "provenance": [
            *(item["provenance"] for item in evidence),
            provenance(
                "derived",
                trace_id,
                "attack_applicability.status",
                "applicability conditionsを集約した",
            ),
        ],
        "candidate_flows": list(candidates),
    }


def _aggregate_conditions(flow_results: list[dict[str, Any]]) -> list[dict[str, str]]:
    names = [item["condition"] for item in flow_results[0]["evaluated_conditions"]]
    result = []
    for name in names:
        statuses = [
            next(
                condition["status"]
                for condition in item["evaluated_conditions"]
                if condition["condition"] == name
            )
            for item in flow_results
        ]
        result.append(
            {
                "condition": name,
                "status": "satisfied"
                if "satisfied" in statuses
                else "unknown"
                if "unknown" in statuses
                else "blocked",
            }
        )
    return result


def _condition(
    name: str,
    status: str,
    reason: str,
    *,
    evidence: tuple[dict[str, Any], ...],
) -> dict[str, Any]:
    return {
        "condition": name,
        "status": status,
        "reason": reason,
        "evidence": list(evidence),
        "provenance": [item["provenance"] for item in evidence],
    }


def _evidence(
    kind: str,
    item_id: str,
    field: str,
    value: Any,
    item_provenance: dict[str, str],
) -> dict[str, Any]:
    return {
        "kind": kind,
        "id": item_id,
        "field": field,
        "value": value,
        "provenance": item_provenance,
    }


def _required_specs(
    context: ScenarioContext, requirement: DetectionRequirement | None
) -> tuple[TelemetryRequirement, ...]:
    specs = list(context.required_logs)
    specs.extend(TelemetryRequirement(event_type=value) for value in context.required_telemetry)
    specs.extend(
        TelemetryRequirement(event_type=value) for value in context.required_authentication_logs
    )
    if requirement is not None:
        specs.extend(TelemetryRequirement(event_type=value) for value in requirement.required_logs)
        if requirement.events:
            specs.extend(
                TelemetryRequirement(event_type=value, fields=requirement.fields)
                for value in requirement.events
            )
    return _merge_specs(specs)


def _available_specs(
    context: ScenarioContext, asset: Asset
) -> tuple[tuple[TelemetryRequirement, ...], bool]:
    names = list(asset.logs)
    names.extend(context.available_telemetry)
    names.extend(context.available_log_fields)
    specs = [
        TelemetryRequirement(event_type=name, fields=_context_fields(context, name) or ())
        for name in names
    ]
    declared = bool(
        asset.logs or context.available_telemetry or context.available_log_fields or asset.logsource
    )
    return _merge_specs(specs), declared


def _merge_specs(specs: Iterable[TelemetryRequirement]) -> tuple[TelemetryRequirement, ...]:
    merged: dict[str, tuple[str, set[str]]] = {}
    for spec in specs:
        key = _telemetry_key(spec.event_type)
        display, fields = merged.get(key, (spec.event_type, set()))
        fields.update(_field_key(value) for value in spec.fields)
        merged[key] = (display, fields)
    return tuple(
        TelemetryRequirement(event_type=display, fields=tuple(sorted(fields)))
        for display, fields in merged.values()
    )


def _telemetry_evidence(
    condition: str,
    item: str,
    status: str,
    context: ScenarioContext,
    asset: Asset,
    requirement: DetectionRequirement | None,
) -> dict[str, Any]:
    if condition == "asset_logsource":
        source_type, source_id, field, rationale = (
            "system_model",
            f"asset:{asset.name}",
            "logsource",
            "Assetに明示されたSigma logsource",
        )
    elif requirement is not None and item in requirement.events:
        source_type, source_id, field, rationale = (
            "public_threat_intel",
            f"ATT&CK:{requirement.technique_id}",
            "detection_strategy.analytics.events",
            "ATT&CK Detection Analyticに明示されたイベント",
        )
    elif item in context.required_authentication_logs:
        source_type, source_id, field, rationale = (
            "scenario_author",
            f"scenario:{asset.name}",
            "required_authentication_logs",
            "シナリオ作成者が明示した認証ログ要件",
        )
    else:
        source_type, source_id, field, rationale = (
            "scenario_author",
            f"scenario:{asset.name}",
            "required_logs",
            "シナリオ作成者が明示したテレメトリ要件",
        )
    return _evidence(
        "telemetry",
        item,
        "status",
        status,
        provenance(source_type, source_id, field, rationale),
    )


def _availability_evidence(
    condition: str,
    item: str,
    status: str,
    context: ScenarioContext,
    asset: Asset,
) -> list[dict[str, Any]]:
    """Record the concrete availability declarations used by the decision."""
    evidence: list[dict[str, Any]] = []
    if asset.logs:
        evidence.append(
            _evidence(
                "telemetry",
                item,
                "Asset.logs",
                list(asset.logs),
                provenance(
                    "system_model",
                    f"asset:{asset.name}",
                    "logs",
                    "判定に使ったAssetの取得ログ一覧",
                ),
            )
        )
    if asset.logsource:
        evidence.append(
            _evidence(
                "telemetry",
                item,
                "Asset.logsource",
                dict(asset.logsource),
                provenance(
                    "system_model",
                    f"asset:{asset.name}",
                    "logsource",
                    "判定に使ったAssetのlogsource",
                ),
            )
        )
    if context.available_telemetry:
        evidence.append(
            _evidence(
                "telemetry",
                item,
                "available_telemetry",
                list(context.available_telemetry),
                provenance(
                    "scenario_author",
                    f"scenario:{asset.name}",
                    "available_telemetry",
                    "判定に使ったシナリオの取得テレメトリ一覧",
                ),
            )
        )
    if context.available_log_fields:
        evidence.append(
            _evidence(
                "telemetry",
                item,
                "available_log_fields",
                {
                    name: list(fields)
                    for name, fields in context.available_log_fields.items()
                },
                provenance(
                    "scenario_author",
                    f"scenario:{asset.name}",
                    "available_log_fields",
                    "判定に使ったシナリオの取得フィールド一覧",
                ),
            )
        )
    if not evidence:
        evidence.append(
            _evidence(
                "telemetry",
                item,
                "availability",
                None,
                provenance(
                    "derived",
                    f"scenario:{asset.name}",
                    condition,
                    "取得状況の明示がないためunknownとして扱った",
                ),
            )
        )
    return evidence


def _context_fields(context: ScenarioContext, event_type: str) -> tuple[str, ...] | None:
    """Return explicitly declared fields using the same event alias rules."""
    for name, fields in context.available_log_fields.items():
        if _telemetry_key(name) == _telemetry_key(event_type):
            return fields
    return None


def _logsource_status(asset: Asset, required: tuple[TelemetryRequirement, ...]) -> str:
    if not required:
        return "unknown"
    if not asset.logsource:
        return "unknown"
    values = {_telemetry_key(value) for value in asset.logsource.values()}
    return (
        "available"
        if any(_telemetry_key(item.event_type) in values for item in required)
        else "missing"
    )


def _aggregate_condition_status(statuses: list[str], *, default: str) -> str:
    if not statuses:
        return default
    if "missing" in statuses:
        return "missing"
    if "unknown" in statuses:
        return "unknown"
    return "available"


def _compare_privilege(actual: str, required: str) -> str:
    if _same(actual, required):
        return "satisfied"
    levels = {
        "none": 0,
        "anonymous": 0,
        "guest": 1,
        "user": 2,
        "service": 2,
        "operator": 3,
        "admin": 4,
        "root": 5,
    }
    if actual.casefold() in levels and required.casefold() in levels:
        return (
            "satisfied" if levels[actual.casefold()] >= levels[required.casefold()] else "blocked"
        )
    return "unknown"


def _parse_transition(value: str) -> tuple[str, str] | None:
    parts = re.split(r"\s*(?:->|→|-to-)\s*", value, maxsplit=1, flags=re.IGNORECASE)
    return (parts[0].strip(), parts[1].strip()) if len(parts) == 2 and all(parts) else None


def _flow_id(flow: Flow, index: int) -> str:
    return f"flow-{index}:{flow.source}->{flow.destination}"


def _same(left: str, right: str) -> bool:
    return left.casefold().strip() == right.casefold().strip()


def _telemetry_key(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")
    aliases = {
        "process_creation": "process_creation",
        "process_execution": "process_creation",
        "file_access": "file_event",
        "file_activity": "file_event",
        "network_connection_creation": "network_connection",
        "network_connection": "network_connection",
        "dns_query": "dns",
    }
    return aliases.get(normalized, normalized)


def _field_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", ".", value.casefold()).strip(".")
