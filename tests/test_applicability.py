from pathlib import Path

from threat_to_detection.collectors.attack import AttackDataset
from threat_to_detection.models.system import Asset, SystemModel
from threat_to_detection.services.applicability import evaluate_detection_feasibility
from threat_to_detection.services.pipeline import TracePath, run_pipeline

FIXTURE = Path(__file__).parent / "fixtures/attack/enterprise-attack.json"


def _system(*, logs=("process_creation",), fields=None, flow=None, privilege="user"):
    asset = Asset(
        name="server",
        logs=logs,
        privilege_level=privilege,
    )
    scenario = {
        "scenario_type": "network",
        "entrypoint_type": "network_event",
        "entrypoint": {"type": "network_event", "id": "test-event"},
        "technique_ids": ("T1059",),
        "required_privilege": "user",
        "required_logs": [
            {
                "event_type": "process_creation",
                "fields": ["event_id", "process.command_line"],
            }
        ],
    }
    if fields is not None:
        scenario["available_log_fields"] = {"process_creation": fields}
    return SystemModel(
        scenario=scenario,
        assets=(asset,),
        flows=() if flow is None else (flow,),
    )


def _result(system):
    return run_pipeline(
        system,
        (),
        attack_dataset=AttackDataset.from_json(FIXTURE),
    ).to_mapping(system)


def test_applicable_path_is_kept_when_detection_is_unavailable():
    document = _result(
        _system(
            logs=(),
            flow={
                "from": "internet",
                "to": "server",
                "trust_boundary": "internet-to-dmz",
                "authentication": {"satisfied": True, "method": "certificate"},
                "authorization": {"satisfied": True, "roles": ["user"]},
            },
        )
    )
    record = document["threat_analysis"][0]
    assert record["attack_applicability"]["status"] == "applicable"
    assert record["detection_feasibility"]["status"] == "unavailable"


def test_missing_flow_is_blocked_and_logs_do_not_cause_blocking():
    document = _result(_system(flow=None))
    record = document["threat_analysis"][0]
    assert record["attack_applicability"]["status"] == "blocked"
    assert record["attack_applicability"]["blocked_reason"] == "communication_path"
    assert record["attack_applicability"]["evidence"] == []
    assert record["attack_applicability"]["provenance"]
    assert record["detection_feasibility"]["status"] in {"partial", "detectable"}


def test_undeclared_access_conditions_are_unknown_and_https_is_not_authentication():
    document = _result(
        _system(
            flow={"from": "internet", "to": "server", "protocol": "https"},
        )
    )
    applicability = document["threat_analysis"][0]["attack_applicability"]
    assert applicability["status"] == "unknown"
    assert set(applicability["unknown_reasons"]) >= {
        "trust_boundary",
        "authentication",
        "authorization",
    }


def test_descriptive_access_fields_without_satisfaction_are_unknown():
    document = _result(
        _system(
            flow={
                "from": "internet",
                "to": "server",
                "trust_boundary": "internet-to-dmz",
                "authentication": {"required": True, "method": "password"},
                "authorization": {"required": True, "roles": ["user"]},
            },
        )
    )
    applicability = document["threat_analysis"][0]["attack_applicability"]
    assert applicability["status"] == "unknown"
    assert set(applicability["unknown_reasons"]) >= {"authentication", "authorization"}


def test_strategyless_candidate_has_unknown_detection_feasibility():
    result = evaluate_detection_feasibility(
        {
            "required_logs": ["process_creation"],
            "required_events": ["process_creation"],
            "available_events": ["process_creation"],
            "status": "complete",
        },
        asset=Asset(name="server", logs=("process_creation",)),
        trace_id="strategyless-trace",
        has_detection_requirement=False,
    )
    assert result["status"] == "unknown"


def test_insufficient_privilege_is_blocked():
    system = _system(
        privilege="user",
        flow={
            "from": "internet",
            "to": "server",
            "trust_boundary": "internet-to-dmz",
            "authentication": {"required": False},
            "authorization": {"required": False},
        },
    )
    system = system.model_copy(
        update={
            "scenario": system.scenario.model_copy(update={"required_privilege": "admin"})
        }
    )
    record = _result(system)["threat_analysis"][0]
    assert record["attack_applicability"]["status"] == "blocked"
    assert record["attack_applicability"]["blocked_reason"] == "privilege"


def test_explicit_boundary_mismatch_is_blocked():
    system = _system(
        flow={
            "from": "internet",
            "to": "server",
            "trust_boundary": "internet-to-dmz",
            "authentication": {"required": False},
            "authorization": {"required": False},
        },
    )
    system = system.model_copy(
        update={
            "scenario": system.scenario.model_copy(
                update={"required_trust_boundary": "dmz-to-internal"}
            )
        }
    )
    record = _result(system)["threat_analysis"][0]
    assert record["attack_applicability"]["status"] == "blocked"
    assert record["attack_applicability"]["blocked_reason"] == "trust_boundary"


def test_detection_feasibility_has_partial_and_detectable_states():
    partial = _result(
        _system(
            fields=("event_id",),
            flow={
                "from": "internet",
                "to": "server",
                "trust_boundary": "internet-to-dmz",
                "authentication": {"required": False},
                "authorization": {"required": False},
            },
        )
    )["threat_analysis"][0]
    complete = _result(
        _system(
            fields=("event_id", "process.command_line"),
            flow={
                "from": "internet",
                "to": "server",
                "trust_boundary": "internet-to-dmz",
                "authentication": {"required": False},
                "authorization": {"required": False},
            },
        )
    )["threat_analysis"][0]
    assert partial["detection_feasibility"]["status"] == "partial"
    assert complete["detection_feasibility"]["status"] == "detectable"


def test_trace_path_mapping_exposes_trace_id_and_candidate_before_flag():
    trace = TracePath("server", "", "", "", "T1059", "")
    assert trace.to_mapping()["trace_id"] == trace.path_id
