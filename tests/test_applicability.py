from pathlib import Path

from threat_to_detection.collectors.attack import AttackDataset
from threat_to_detection.models.system import Asset, SystemModel
from threat_to_detection.services.pipeline import run_pipeline

ATTACK_FIXTURE = Path(__file__).parent / "fixtures/attack/enterprise-attack.json"


def _document(
    *,
    flows=(),
    logs=("process_creation",),
    available_telemetry=(),
    available_log_fields=None,
    scenario_overrides=None,
):
    scenario = {
        "scenario_type": "malware",
        "entrypoint_type": "technique",
        "technique_ids": ("T1059",),
        "required_privilege": "user",
        "authentication": {"required": False},
        "authorization": {"required": False},
        "required_logs": [
            {"event_type": "process_creation", "fields": ["event_id", "process.command_line"]}
        ],
        "available_telemetry": available_telemetry,
        "available_log_fields": available_log_fields or {},
    }
    scenario.update(scenario_overrides or {})
    system = SystemModel(
        scenario=scenario,
        assets=(
            Asset(
                name="endpoint",
                exposed_to=("internet",),
                trust_zone="dmz",
                privilege_level="user",
                logs=logs,
                logsource={"category": "process_creation"} if logs else None,
            ),
        ),
        flows=flows,
    )
    return run_pipeline(
        system,
        (),
        attack_dataset=AttackDataset.from_json(ATTACK_FIXTURE),
    ).to_mapping(system)


def _valid_flow():
    return {
        "from": "internet",
        "to": "endpoint",
        "trust_boundary": "internet-to-dmz",
        "authentication": {"required": False},
        "authorization": {"required": False},
    }


def test_applicable_and_unavailable_are_independent():
    document = _document(
        flows=(_valid_flow(),),
        logs=("network_connection",),
        available_telemetry=("network_connection",),
    )
    trace = document["trace_paths"][0]

    assert trace["attack_applicability"]["status"] == "applicable"
    assert trace["detection_feasibility"]["status"] == "unavailable"
    assert trace["detection_feasibility_status"] == "unavailable"
    assert document["threat_analysis"][0]["attack_applicability"]["status"] == "applicable"
    assert document["threat_analysis"][0]["detection_feasibility_status"] == "unavailable"
    assert document["mapping_gaps"] == []


def test_blocked_is_reported_for_missing_flow_and_explicit_access_conflict():
    missing_flow = _document(flows=())
    assert missing_flow["trace_paths"][0]["attack_applicability"]["status"] == "blocked"

    conflict = _document(
        flows=(
            {
                "from": "internet",
                "to": "endpoint",
                "trust_boundary": "internet-to-dmz",
                "authentication": {"required": True},
                "authorization": {"required": False},
            },
        )
    )
    assert conflict["trace_paths"][0]["attack_applicability"]["status"] == "blocked"
    conditions = conflict["trace_paths"][0]["attack_applicability"]["candidate_flows"][0][
        "evaluated_conditions"
    ]
    assert {item["status"] for item in conditions} >= {"blocked"}


def test_unknown_does_not_infer_authentication_from_https_or_flow():
    document = _document(
        flows=({"from": "internet", "to": "endpoint", "protocol": "https"},),
        scenario_overrides={
            "required_privilege": None,
            "authentication": None,
            "authorization": None,
        },
    )
    applicability = document["trace_paths"][0]["attack_applicability"]
    assert applicability["status"] == "unknown"
    assert {item["status"] for item in applicability["evaluated_conditions"]} >= {"unknown"}


def test_access_details_missing_from_flow_remain_unknown():
    document = _document(
        flows=(
            {
                "from": "internet",
                "to": "endpoint",
                "trust_boundary": "internet-to-dmz",
                "authentication": {"required": True},
                "authorization": {"required": False},
            },
        ),
        scenario_overrides={
            "authentication": {
                "required": True,
                "satisfied": True,
                "method": "service_account",
            }
        },
    )
    applicability = document["trace_paths"][0]["attack_applicability"]
    assert applicability["status"] == "unknown"
    authentication = next(
        item
        for item in applicability["evaluated_conditions"]
        if item["condition"] == "authentication"
    )
    assert authentication["status"] == "unknown"


def test_detection_feasibility_partial_detectable_and_unknown():
    partial = _document(
        flows=(_valid_flow(),),
        logs=("process_creation",),
        available_telemetry=("process_creation",),
        available_log_fields={
            "process_creation": ["event_id"],
            "Event ID 1": ["process.command_line"],
        },
    )
    assert partial["trace_paths"][0]["detection_feasibility"]["status"] == "partial"

    detectable = _document(
        flows=(_valid_flow(),),
        logs=("process_creation", "Event ID 1"),
        available_telemetry=("process_creation", "Event ID 1"),
        available_log_fields={
            "process_creation": ["event_id", "process.command_line"],
            "Event ID 1": ["process.command_line"],
        },
    )
    assert detectable["trace_paths"][0]["detection_feasibility"]["status"] == "detectable"

    unknown = _document(flows=(_valid_flow(),), logs=(), available_telemetry=())
    assert unknown["trace_paths"][0]["detection_feasibility"]["status"] == "unknown"


def test_multiple_flows_keep_candidate_evidence_and_use_applicable_candidate():
    document = _document(
        flows=(
            {
                "from": "internet",
                "to": "endpoint",
                "trust_boundary": "wrong-boundary",
                "authentication": {"required": True},
                "authorization": {"required": False},
            },
            _valid_flow(),
        )
    )
    applicability = document["trace_paths"][0]["attack_applicability"]
    assert applicability["status"] == "applicable"
    assert len(applicability["candidate_flows"]) == 2
    assert {item["status"] for item in applicability["candidate_flows"]} == {
        "blocked",
        "applicable",
    }


def test_blocked_and_unknown_candidates_aggregate_to_unknown():
    document = _document(
        flows=(
            {
                "from": "internet",
                "to": "endpoint",
                "trust_boundary": "wrong-boundary",
                "authentication": {"required": True},
                "authorization": {"required": False},
            },
            {"from": "internet", "to": "endpoint", "protocol": "https"},
        ),
        scenario_overrides={
            "authentication": None,
            "authorization": None,
            "required_privilege": None,
            "required_trust_boundary": "expected-boundary",
        },
    )
    applicability = document["trace_paths"][0]["attack_applicability"]
    assert applicability["status"] == "unknown"
    assert {item["status"] for item in applicability["candidate_flows"]} == {
        "blocked",
        "unknown",
    }


def test_evidence_provenance_distinguishes_input_owners():
    document = _document(flows=(_valid_flow(),))
    trace = document["trace_paths"][0]
    source_types = {
        item["provenance"]["source_type"] for item in trace["attack_applicability"]["evidence"]
    }
    assert {"system_model", "scenario_author"} <= source_types
    assert any(
        item["source_type"] == "derived" for item in trace["attack_applicability"]["provenance"]
    )
    assert any(
        item["field"] == "exposed_to" for item in trace["attack_applicability"]["evidence"]
    )
    assert any(
        item["field"] == "Asset.logs" for item in trace["detection_feasibility"]["evidence"]
    )


def test_legacy_coverage_and_strict_feasibility_are_explicitly_distinct():
    document = _document(
        flows=(_valid_flow(),),
        available_log_fields={"process_creation": ["event_id", "process.command_line"]},
    )
    record = document["threat_analysis"][0]
    assert record["coverage"]["status"] == "complete"
    assert record["detection_feasibility"]["status"] == "partial"
    assert record["detection_feasibility_status"] == record["detection_feasibility"]["status"]
