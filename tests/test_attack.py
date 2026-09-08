import json
from pathlib import Path

import pytest

from threat_to_detection.collectors.attack import AttackDataset
from threat_to_detection.mappers.capec_to_attack import (
    map_attack_to_detection,
    map_capec_to_attack,
)

FIXTURE = Path(__file__).parent / "fixtures/attack/enterprise-attack.json"


def test_attack_stix_is_normalized_and_indexed_by_capec() -> None:
    dataset = AttackDataset.from_json(FIXTURE)

    techniques = map_capec_to_attack("CAPEC-100", dataset)

    assert [technique.technique_id for technique in techniques] == ["T1059", "T1105"]
    assert techniques[0].name == "Example Technique"
    assert techniques[0].tactics == ("execution",)
    assert techniques[0].related_capec_ids == ("CAPEC-100",)


def test_unmapped_capec_returns_empty_tuple() -> None:
    dataset = AttackDataset.from_json(FIXTURE)

    assert map_capec_to_attack("CAPEC-999", dataset) == ()


def test_detection_strategy_is_normalized_to_telemetry_requirements() -> None:
    dataset = AttackDataset.from_json(FIXTURE)

    requirements = map_attack_to_detection("t1059", dataset)

    assert len(requirements) == 1
    requirement = requirements[0]
    assert requirement.strategy_id == "DET0001"
    assert [analytic.analytic_id for analytic in requirement.analytics] == ["AN0001"]
    assert requirement.required_logs == ("Process Creation",)
    assert requirement.events == ("Event ID 1",)
    assert requirement.fields == ("process.command_line",)
    assert requirement.data_components[0].data_source_name == "Endpoint Telemetry"
    assert requirement.data_components[0].data_source_id == (
        "x-mitre-data-source--00000000-0000-4000-8000-000000000013"
    )


def test_technique_without_detection_strategy_is_safe() -> None:
    dataset = AttackDataset.from_json(FIXTURE)

    assert map_attack_to_detection("T1105", dataset) == ()


def test_non_data_component_reference_is_ignored(tmp_path: Path) -> None:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    analytic = next(item for item in document["objects"] if item.get("type") == "x-mitre-analytic")
    analytic["x_mitre_log_source_references"][0]["x_mitre_data_component_ref"] = (
        "x-mitre-data-source--00000000-0000-4000-8000-000000000013"
    )
    path = tmp_path / "attack.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    dataset = AttackDataset.from_json(path)

    analytic_result = map_attack_to_detection("T1059", dataset)[0].analytics[0]
    assert analytic_result.data_components == ()
    assert analytic_result.events == ("Event ID 1",)


@pytest.mark.parametrize("flag", ["revoked", "x_mitre_deprecated"])
def test_revoked_or_deprecated_detects_relationship_is_ignored(
    flag: str, tmp_path: Path
) -> None:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    relationship = next(item for item in document["objects"] if item.get("type") == "relationship")
    relationship[flag] = True
    path = tmp_path / "attack.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    dataset = AttackDataset.from_json(path)

    assert map_attack_to_detection("T1059", dataset) == ()


def test_strategy_stix_id_is_fallback_when_external_id_is_missing(tmp_path: Path) -> None:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    strategy = next(
        item
        for item in document["objects"]
        if item.get("type") == "x-mitre-detection-strategy"
    )
    strategy["external_references"] = []
    path = tmp_path / "attack.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    dataset = AttackDataset.from_json(path)

    requirement = map_attack_to_detection("T1059", dataset)[0]
    assert requirement.strategy_id == strategy["id"]


@pytest.mark.parametrize("object_type,flag", [
    ("x-mitre-data-component", "revoked"),
    ("x-mitre-data-source", "x_mitre_deprecated"),
])
def test_revoked_or_deprecated_telemetry_is_not_adopted(
    object_type: str, flag: str, tmp_path: Path
) -> None:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    telemetry = next(item for item in document["objects"] if item.get("type") == object_type)
    telemetry[flag] = True
    path = tmp_path / "attack.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    requirement = map_attack_to_detection("T1059", AttackDataset.from_json(path))[0]

    if object_type == "x-mitre-data-component":
        assert requirement.data_components == ()
    else:
        component = requirement.data_components[0]
        assert component.data_source_id is None
        assert component.data_source_name is None


def test_repeated_component_references_merge_logs_and_analytics_in_order(
    tmp_path: Path,
) -> None:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    objects = document["objects"]
    analytic = next(item for item in objects if item.get("type") == "x-mitre-analytic")
    component_ref = analytic["x_mitre_log_source_references"][0][
        "x_mitre_data_component_ref"
    ]
    analytic["x_mitre_log_source_references"].append(
        {"x_mitre_data_component_ref": component_ref, "name": "ETW"}
    )
    second_analytic = json.loads(json.dumps(analytic))
    second_analytic["id"] = second_analytic["id"].replace("0011", "0014")
    second_analytic["external_references"][0]["external_id"] = "AN0002"
    second_analytic["x_mitre_log_source_references"] = [
        {"x_mitre_data_component_ref": component_ref, "name": "Auditd"}
    ]
    objects.append(second_analytic)
    strategy = next(
        item
        for item in objects
        if item.get("type") == "x-mitre-detection-strategy"
    )
    strategy["x_mitre_analytic_refs"].append(second_analytic["id"])
    path = tmp_path / "attack.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    requirement = map_attack_to_detection("T1059", AttackDataset.from_json(path))[0]

    assert [analytic.analytic_id for analytic in requirement.analytics] == [
        "AN0001",
        "AN0002",
    ]
    assert len(requirement.data_components) == 1
    component = requirement.data_components[0]
    assert component.name == "Process Creation"
    assert component.log_sources == ("Sysmon", "ETW", "Auditd")


@pytest.mark.parametrize("attribute", ["name", "id"])
def test_component_identifier_and_name_type_errors_are_ignored(
    attribute: str, tmp_path: Path
) -> None:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    component = next(
        item for item in document["objects"] if item.get("type") == "x-mitre-data-component"
    )
    component[attribute] = 123
    path = tmp_path / "attack.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    requirement = map_attack_to_detection("T1059", AttackDataset.from_json(path))[0]

    assert requirement.data_components == ()
