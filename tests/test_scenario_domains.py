from pathlib import Path

import pytest

from threat_to_detection.collectors.attack import AttackDataset
from threat_to_detection.models.system import Asset, SystemModel, load_system
from threat_to_detection.services.pipeline import run_analysis, run_pipeline

FIXTURE = Path(__file__).parent / "fixtures/attack/enterprise-attack.json"


def test_non_cve_malware_scenario_maps_technique_to_requirement() -> None:
    system = SystemModel(
        scenario={
            "scenario_type": "malware",
            "entrypoint_type": "malware_behavior",
            "entrypoint": {
                "type": "malware_behavior",
                "id": "behavior-process-execution",
                "name": "Process execution",
                "behaviors": ("starts a child process",),
            },
            "attacker_actions": ("execute a payload",),
            "technique_ids": ("T1059",),
            "evidence": ("safe synthetic behavior record",),
            "confidence": "medium",
        },
        assets=(Asset(name="endpoint", logs=("process_creation",)),),
    )

    result = run_pipeline(
        system,
        (),
        attack_dataset=AttackDataset.from_json(FIXTURE),
    )

    assert result.relevant_vulnerabilities["endpoint"] == ()
    assert [item.technique_id for item in result.detection_requirements["endpoint"]] == [
        "T1059"
    ]
    assert result.traces[0].cve_id == ""
    document = result.to_mapping(system)
    record = document["threat_analysis"][0]
    assert record["scenario_type"] == "malware"
    assert record["entrypoint_type"] == "malware_behavior"
    assert record["coverage"]["status"] == "complete"
    assert record["coverage"]["coverage_ratio"] == 1.0


def test_non_cve_run_analysis_can_generate_sigma_without_capec() -> None:
    system = SystemModel(
        scenario={
            "scenario_type": "network",
            "entrypoint": {"type": "network_event", "id": "network-c2"},
            "technique_ids": ("T1059",),
        },
        assets=(Asset(name="endpoint", logs=("process_creation",)),),
    )

    result = run_analysis(
        system,
        vulnerabilities=(),
        attack_dataset=AttackDataset.from_json(FIXTURE),
    )

    assert result.errors == ()
    assert len(result.sigma_rules["endpoint"]) == 1
    assert result.sigma_rules["endpoint"][0].evidence.cve_ids == ()


def test_invalid_domain_entrypoint_is_rejected() -> None:
    with pytest.raises(ValueError, match="malware"):
        SystemModel(
            scenario={
                "scenario_type": "malware",
                "entrypoint_type": "cve",
            }
        )


def test_flat_scenario_fields_are_accepted_and_legacy_defaults_remain() -> None:
    legacy = load_system("examples/web-system.yaml")
    assert legacy.scenario_type == "vulnerability"
    assert legacy.entrypoint_type == "cve"

    system = SystemModel(
        scenario_type="identity",
        entrypoint_type="identity_event",
        entrypoint={"type": "identity_event", "id": "login-anomaly"},
        technique_ids=("T1059",),
    )
    assert system.scenario_type == "identity"
    assert system.scenario.entrypoint_type == "identity_event"


def test_evaluation_identity_behavior_document_is_loadable() -> None:
    system = load_system(
        "evaluations/scenarios/scenario-06-identity-credential-access.yaml"
    )

    assert system.scenario_type == "identity"
    assert system.entrypoint_type == "identity_behavior"
    assert system.scenario.required_telemetry == ("identity.authentication",)


def test_control_scenario_is_explicit_no_match_without_attack_path() -> None:
    system = load_system(
        "evaluations/scenarios/scenario-10-control-normal-administration.yaml"
    )
    result = run_analysis(system, vulnerabilities=())

    assert result.errors == ()
    document = result.to_mapping(system)
    assert document["analysis_outcome"] == "control"
    assert document["status"] == "success"
    assert document["assets"][system.assets[0].name]["sigma_rules"] == []


def test_vulnerability_evaluation_does_not_duplicate_entrypoint_techniques() -> None:
    system = load_system("evaluations/scenarios/scenario-01-cve-example-process.yaml")

    assert system.scenario.technique_ids == ()


def test_vulnerability_evaluation_asset_preserves_software_and_logs() -> None:
    system = load_system("evaluations/scenarios/scenario-01-cve-example-process.yaml")
    asset = system.assets[0]

    assert asset.name == "web-server"
    assert asset.software[0].vendor == "vendor"
    assert asset.software[0].product == "example-product"
    assert asset.software[0].version == "1.0"
    assert asset.logs == ("process_creation",)
    assert asset.logsource == {"category": "process_creation"}


def test_threat_analysis_includes_security_boundary_and_access_context() -> None:
    system = SystemModel(
        scenario={
            "scenario_type": "malware",
            "entrypoint": {"type": "malware_behavior", "id": "behavior"},
            "technique_ids": ("T1059",),
            "required_privilege": "user",
            "privilege_transition": "user-to-admin",
            "required_authentication_logs": ("identity.authentication",),
        },
        assets=(
            Asset(name="endpoint", trust_zone="workstation", privilege_level="user"),
            Asset(name="server", trust_zone="internal", privilege_level="admin"),
        ),
        flows=(
            {
                "from": "endpoint",
                "to": "server",
                "trust_boundary": "workstation-to-internal",
                "authentication": {
                    "required": True,
                    "method": "service_account",
                    "principal": "endpoint-agent",
                },
                "authorization": {
                    "required": True,
                    "roles": ["operator"],
                    "privilege": "admin",
                },
            },
        ),
    )

    result = run_pipeline(
        system,
        (),
        attack_dataset=AttackDataset.from_json(FIXTURE),
    )
    record = result.to_mapping(system)["threat_analysis"][0]
    assert record["trust_zone"] == "workstation"
    assert record["privilege_level"] == "user"
    assert record["trust_boundaries"] == ["workstation-to-internal"]
    assert record["flow_security"][0]["authentication"]["principal"] == "endpoint-agent"
    assert record["flow_security"][0]["authorization"]["roles"] == ["operator"]
    assert record["required_privilege"] == "user"
    assert record["privilege_transition"] == "user-to-admin"
    assert record["required_authentication_logs"] == ["identity.authentication"]


def test_telemetry_coverage_keeps_required_fields_and_authentication_logs() -> None:
    system = SystemModel(
        scenario={
            "scenario_type": "identity",
            "entrypoint_type": "identity_event",
            "entrypoint": {"type": "identity_event", "id": "login"},
            "required_logs": [
                {"event_type": "identity.authentication", "fields": ["user", "outcome"]}
            ],
            "required_authentication_logs": ("identity.authentication",),
        },
        assets=(
            Asset(
                name="idp",
                logs=("identity_authentication",),
            ),
        ),
    )
    result = run_pipeline(system, ())
    coverage = result.to_mapping(system)["threat_analysis"][0]["coverage"]

    assert coverage["required_logs"] == [
        {"event_type": "identity.authentication", "fields": ["outcome", "user"]}
    ]
    assert coverage["covered_events"] == ["identity.authentication"]
    assert coverage["missing_fields"] == [
        "identity.authentication.outcome",
        "identity.authentication.user",
    ]
    assert coverage["status"] == "partial"


def test_unspecified_authentication_and_authorization_are_unknown() -> None:
    system = SystemModel(
        flows=({"from": "client", "to": "server"},),
    )
    flow = system.flows[0]
    assert flow.authentication is None
    assert flow.authorization is None

    explicit = SystemModel(
        flows=(
            {
                "from": "client",
                "to": "server",
                "authentication": {"required": False},
                "authorization": {"required": False},
            },
        )
    )
    assert explicit.flows[0].authentication.required is False
    assert explicit.flows[0].authorization.required is False
