from __future__ import annotations

import json
from pathlib import Path

import yaml

from threat_to_detection.cli import evaluate_threat_universe_command
from threat_to_detection.models.system import Flow, load_system
from threat_to_detection.models.threat import ThreatApplicabilityProfile
from threat_to_detection.services.applicability import evaluate_attack_applicability
from threat_to_detection.services.threat_universe import evaluate_threat_universe

ROOT = Path(__file__).parents[1]
UNIVERSE = ROOT / "evaluations/threat-universe.yaml"
SYSTEM = ROOT / "evaluations/threat-universe-system.yaml"


def test_threat_universe_samples_broad_population_and_keeps_statuses_separate() -> None:
    result = evaluate_threat_universe(UNIVERSE)

    assert result["sampling"]["population_count"] == 18
    assert result["sampling"]["sampled_candidate_count"] == 12
    assert result["summary"] == {
        "population_count": 18,
        "sampled_candidate_count": 12,
        "before_candidate_count": 12,
        "applicable_count": 5,
        "blocked_count": 3,
        "unknown_count": 4,
        "candidate_reduction_rate": 0.25,
        "blocked_reasons": {"communication_path": 2, "trust_boundary": 1},
        "unknown_reasons": {"preconditions": 3, "trust_boundary": 1},
    }
    assert result["expected_outcome"]["status"] == "passed"
    assert {item["domain"] for item in result["candidates"]} == {
        "command_and_control",
        "discovery",
        "execution",
        "initial_access",
        "lateral_movement",
        "persistence",
    }
    assert all(
        item["source"]["source_type"] == "public_threat_intel"
        for item in result["candidates"]
    )
    assert all(item["applicability_profile"]["rationale"] for item in result["candidates"])


def test_threat_universe_sampling_is_reproducible() -> None:
    first = evaluate_threat_universe(UNIVERSE)
    second = evaluate_threat_universe(UNIVERSE)

    assert first["sampling"]["selected_threat_ids"] == second["sampling"]["selected_threat_ids"]
    assert first["summary"] == second["summary"]


def test_threat_universe_expected_outcome_detects_fixture_drift(tmp_path: Path) -> None:
    document = yaml.safe_load(UNIVERSE.read_text(encoding="utf-8"))
    document["expected_outcome"]["status_counts"]["applicable"] = 999
    path = tmp_path / "universe.yaml"
    path.write_text(yaml.safe_dump(document, allow_unicode=True, sort_keys=False), encoding="utf-8")

    result = evaluate_threat_universe(path, system_path=SYSTEM)

    assert result["expected_outcome"]["status"] == "failed"
    assert "status_counts" in result["expected_outcome"]["mismatches"]


def test_threat_universe_cli_writes_machine_and_human_outputs(tmp_path: Path) -> None:
    output = tmp_path / "result.json"
    report = tmp_path / "report.md"

    assert evaluate_threat_universe_command(
        [
            "--universe",
            str(UNIVERSE),
            "--output",
            str(output),
            "--report",
            str(report),
        ]
    ) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["expected_outcome"]["status"] == "passed"
    assert "# 脅威候補母集団の適用可否評価" in report.read_text(encoding="utf-8")


def test_committed_threat_universe_result_matches_regeneration(tmp_path: Path) -> None:
    output = tmp_path / "result.json"
    report = tmp_path / "report.md"

    assert evaluate_threat_universe_command(
        [
            "--universe",
            "evaluations/threat-universe.yaml",
            "--output",
            str(output),
            "--report",
            str(report),
        ]
    ) == 0
    regenerated = json.loads(output.read_text(encoding="utf-8"))
    committed = json.loads(
        (ROOT / "evaluations/threat-universe-results.json").read_text(encoding="utf-8")
    )

    assert regenerated == committed


def test_outbound_profile_filters_flow_destination() -> None:
    system = load_system(SYSTEM)
    profile = ThreatApplicabilityProfile(
        flow_direction="outbound",
        flow_source="web-server",
        flow_destination="internet",
        protocol="https",
        trust_boundary_required=False,
        authentication_required=False,
        authorization_required=False,
        privilege_required=False,
        rationale="Regression profile for outbound counterparty matching.",
    )
    extra_https_flow = Flow(
        **{
            "from": "web-server",
            "to": "database",
            "protocol": "https",
            "trust_boundary": "dmz-to-internal",
            "authentication": {"required": False},
            "authorization": {"required": False},
        }
    )
    system = system.model_copy(update={"flows": (*system.flows, extra_https_flow)})

    result = evaluate_attack_applicability(
        system,
        asset=next(asset for asset in system.assets if asset.name == "web-server"),
        trace_id="outbound-destination-regression",
        profile=profile,
    )

    assert result["status"] == "applicable"
    assert [(item["from"], item["to"]) for item in result["flow_evaluations"]] == [
        ("web-server", "internet")
    ]


def test_blocked_flow_dominates_unknown_common_precondition() -> None:
    system = load_system(SYSTEM)
    profile = ThreatApplicabilityProfile(
        flow_direction="inbound",
        flow_source="internet",
        flow_destination="web-server",
        protocol="https",
        trust_boundary_required=True,
        required_trust_boundary="unrelated-boundary",
        authentication_required=False,
        authorization_required=False,
        privilege_required=False,
        required_preconditions=("undeclared_precondition",),
        rationale="Regression profile for status aggregation precedence.",
    )

    result = evaluate_attack_applicability(
        system,
        asset=next(asset for asset in system.assets if asset.name == "web-server"),
        trace_id="blocked-over-unknown-regression",
        profile=profile,
    )

    assert result["status"] == "blocked"
    assert result["blocked_reasons"] == ["trust_boundary"]
    assert result["unknown_reasons"] == []
