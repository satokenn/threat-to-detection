from __future__ import annotations

import pytest
import yaml

from threat_to_detection.models.detection import (
    DataComponent,
    DetectionAnalytic,
    DetectionRequirement,
)
from threat_to_detection.models.sigma import SigmaEvidence, SigmaRule
from threat_to_detection.models.threat import Evidence
from threat_to_detection.reporters.sigma import (
    detection_requirement_to_sigma,
    render_sigma_yaml,
    sigma_rule_matches_event,
)


def _requirement() -> DetectionRequirement:
    return DetectionRequirement(
        technique_id="T1059",
        strategy_id="DET0001",
        strategy_name="Process execution monitoring",
        analytics=(
            DetectionAnalytic(
                analytic_id="AN0001",
                name="Process analytic",
                description="Observe suspicious process execution.",
                data_components=(
                    DataComponent(
                        component_id="DC0001",
                        name="Process Creation",
                        log_sources=("Sysmon",),
                    ),
                ),
                events=("Event ID 1",),
                fields=("process.command_line",),
            ),
        ),
    )


def test_detection_requirement_becomes_conservative_sigma_rule() -> None:
    rule = detection_requirement_to_sigma(
        _requirement(),
        evidence={"cves": "CVE-2024-0001", "cwes": ["CWE-78"], "capecs": ["CAPEC-88"]},
    )

    assert rule.title == "Process execution monitoring"
    assert dict(rule.logsource) == {"category": "process_creation"}
    assert rule.detection == {
        "selection": {"EventID": 1, "process.command_line|exists": True},
        "condition": "selection",
    }
    assert rule.tags == ("attack.t1059",)
    assert rule.evidence.cve_ids == ("CVE-2024-0001",)
    assert rule.evidence.cwe_ids == ("CWE-78",)
    assert rule.evidence.capec_ids == ("CAPEC-88",)
    assert "suspicious values were not specified" in rule.description


def test_sigma_rule_has_stable_identity_and_candidate_kind() -> None:
    rule = detection_requirement_to_sigma(
        _requirement(),
        rule_id="00000000-0000-5000-8000-000000000001",
    )

    assert rule.rule_id == "00000000-0000-5000-8000-000000000001"
    assert rule.rule_kind == "detection_candidate"
    document = yaml.safe_load(render_sigma_yaml(rule))
    assert document["id"] == rule.rule_id
    assert document["x_threat_to_detection"]["rule_kind"] == "detection_candidate"


def test_fixture_evaluator_checks_generated_event_and_field_predicates() -> None:
    rule = detection_requirement_to_sigma(_requirement())

    assert sigma_rule_matches_event(
        rule, {"EventID": 1, "process.command_line": "/bin/example"}
    )
    assert not sigma_rule_matches_event(
        rule, {"EventID": 3, "process.command_line": "/bin/example"}
    )
    assert not sigma_rule_matches_event(rule, {"EventID": 1})


def test_sigma_yaml_round_trip_keeps_provenance() -> None:
    rule = detection_requirement_to_sigma(
        _requirement(), evidence=SigmaEvidence(references=("https://example.test/source",))
    )
    document = yaml.safe_load(render_sigma_yaml(rule))

    assert document["title"] == "Process execution monitoring"
    assert document["tags"] == ["attack.t1059"]
    assert document["references"] == ["https://example.test/source"]
    assert document["x_threat_to_detection"]["references"] == [
        "https://example.test/source"
    ]


def test_existing_evidence_shape_is_accepted() -> None:
    rule = detection_requirement_to_sigma(
        _requirement(),
        evidence=(Evidence("NVD", "CVE-2024-0001", rationale="NVD record"),),
    )

    assert rule.evidence.cve_ids == ("CVE-2024-0001",)
    assert rule.evidence.source == "NVD"
    assert rule.evidence.rationale == "NVD record"


def test_multiple_legacy_evidence_records_are_retained_in_yaml() -> None:
    rule = detection_requirement_to_sigma(
        _requirement(),
        evidence=(
            Evidence("NVD", "CVE-2024-0001", "NVD record", "high", "https://nvd.test/1"),
            Evidence("CWE", "CWE-78", "Weakness record", "medium", "https://cwe.test/78"),
        ),
        cve_ids=("CVE-2024-0002",),
    )
    document = yaml.safe_load(render_sigma_yaml(rule))
    provenance = document["x_threat_to_detection"]["provenance"]

    assert len(rule.evidence.provenance) == 2
    assert rule.evidence.source == "NVD"  # legacy scalar accessor remains stable
    assert rule.evidence.cve_ids == ("CVE-2024-0001", "CVE-2024-0002")
    assert rule.evidence.cwe_ids == ("CWE-78",)
    assert [item["source_id"] for item in provenance] == ["CVE-2024-0001", "CWE-78"]
    assert [item["confidence"] for item in provenance] == ["high", "medium"]
    assert document["x_threat_to_detection"]["cve_ids"] == [
        "CVE-2024-0001",
        "CVE-2024-0002",
    ]


def test_none_items_in_evidence_are_ignored() -> None:
    rule = detection_requirement_to_sigma(
        _requirement(), evidence={"cves": [None, "CVE-2024-0001"], "notes": [None]}
    )

    assert rule.evidence.cve_ids == ("CVE-2024-0001",)
    assert "None" not in rule.evidence.notes


def test_multiple_event_ids_are_or_values_in_one_selector() -> None:
    requirement = _requirement()
    analytic = requirement.analytics[0]
    requirement = DetectionRequirement(
        technique_id=requirement.technique_id,
        strategy_id=requirement.strategy_id,
        strategy_name=requirement.strategy_name,
        analytics=(
            DetectionAnalytic(
                analytic_id=analytic.analytic_id,
                name=analytic.name,
                data_components=analytic.data_components,
                events=("Event ID 1", "Event ID 3"),
            ),
        ),
    )

    rule = detection_requirement_to_sigma(requirement)

    assert rule.detection["selection"]["EventID"] == [1, 3]


def test_unparsed_event_is_provenance_only_when_field_exists() -> None:
    requirement = _requirement()
    analytic = requirement.analytics[0]
    requirement = DetectionRequirement(
        technique_id=requirement.technique_id,
        strategy_id=requirement.strategy_id,
        strategy_name=requirement.strategy_name,
        analytics=(
            DetectionAnalytic(
                analytic_id=analytic.analytic_id,
                name=analytic.name,
                data_components=analytic.data_components,
                events=("Process start telemetry",),
                fields=analytic.fields,
            ),
        ),
    )

    rule = detection_requirement_to_sigma(requirement)

    assert rule.detection["selection"] == {"process.command_line|exists": True}
    assert "event.channel" not in rule.detection["selection"]
    assert "Process start telemetry" in rule.evidence.notes[0]
    assert "not used as detection" in rule.description


def test_unparsed_event_without_fields_is_rejected() -> None:
    requirement = _requirement()
    analytic = requirement.analytics[0]
    requirement = DetectionRequirement(
        technique_id=requirement.technique_id,
        strategy_id=requirement.strategy_id,
        strategy_name=requirement.strategy_name,
        analytics=(
            DetectionAnalytic(
                analytic_id=analytic.analytic_id,
                name=analytic.name,
                data_components=analytic.data_components,
                events=("Process start telemetry",),
            ),
        ),
    )

    with pytest.raises(ValueError, match="not parseable"):
        detection_requirement_to_sigma(requirement)


def test_unknown_logsource_is_rejected() -> None:
    requirement = DetectionRequirement(
        technique_id="T1059",
        strategy_id="DET0001",
        strategy_name="Unknown telemetry",
        analytics=(
            DetectionAnalytic(
                analytic_id="AN0001",
                name="Unknown analytic",
                data_components=(
                    DataComponent(component_id="DC0001", name="Vendor-specific stream"),
                ),
                fields=("vendor.field",),
            ),
        ),
    )

    with pytest.raises(ValueError, match="logsource could not be determined"):
        detection_requirement_to_sigma(requirement)


def test_logsource_matching_is_exact_and_explicit_override_is_supported() -> None:
    requirement = DetectionRequirement(
        technique_id="T1059",
        strategy_id="DET0001",
        strategy_name="Process telemetry",
        analytics=(
            DetectionAnalytic(
                analytic_id="AN0001",
                name="Process analytic",
                data_components=(
                    DataComponent(component_id="DC0001", name="Process Creation telemetry"),
                ),
                events=("Event ID 1",),
            ),
        ),
    )

    with pytest.raises(ValueError, match="logsource could not be determined"):
        detection_requirement_to_sigma(requirement)
    rule = detection_requirement_to_sigma(
        requirement, logsource_override={"product": "windows"}
    )
    assert rule.logsource == {"product": "windows"}


def test_field_names_are_stripped_and_modifiers_are_not_doubled() -> None:
    requirement = _requirement()
    analytic = requirement.analytics[0]
    requirement = DetectionRequirement(
        technique_id=requirement.technique_id,
        strategy_id=requirement.strategy_id,
        strategy_name=requirement.strategy_name,
        analytics=(
            DetectionAnalytic(
                analytic_id=analytic.analytic_id,
                name=analytic.name,
                data_components=analytic.data_components,
                fields=(" process.command_line ",),
            ),
        ),
    )

    rule = detection_requirement_to_sigma(requirement)

    assert rule.detection["selection"] == {"process.command_line|exists": True}


@pytest.mark.parametrize("field_name", ["   ", "process.command_line|contains"])
def test_invalid_field_names_are_rejected(field_name: str) -> None:
    requirement = _requirement()
    analytic = requirement.analytics[0]
    requirement = DetectionRequirement(
        technique_id=requirement.technique_id,
        strategy_id=requirement.strategy_id,
        strategy_name=requirement.strategy_name,
        analytics=(
            DetectionAnalytic(
                analytic_id=analytic.analytic_id,
                name=analytic.name,
                data_components=analytic.data_components,
                fields=(field_name,),
            ),
        ),
    )

    with pytest.raises(ValueError, match="field"):
        detection_requirement_to_sigma(requirement)


def test_windows_logsource_derives_product_without_tuple_shape() -> None:
    requirement = DetectionRequirement(
        technique_id="T1059",
        strategy_id="DET0001",
        strategy_name="Windows event monitoring",
        analytics=(
            DetectionAnalytic(
                analytic_id="AN0001",
                name="Windows analytic",
                data_components=(
                    DataComponent(component_id="DC0001", name="Windows Event Log"),
                ),
                events=("Event ID 4624",),
            ),
        ),
    )

    rule = detection_requirement_to_sigma(requirement)

    assert rule.logsource == {"product": "windows"}


def test_rule_validation_rejects_missing_sigma_required_parts() -> None:
    with pytest.raises(ValueError, match="logsource"):
        SigmaRule(title="x", logsource={}, detection={"condition": "selection"})

    with pytest.raises(ValueError, match="no event or field"):
        detection_requirement_to_sigma(
            DetectionRequirement("T1000", "DET", "No telemetry")
        )


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"title": "x" * 257}, "title"),
        ({"logsource": {"category": 1}}, "logsource"),
        ({"tags": ("attack.t1059", 1)}, "tags"),
        ({"references": ("https://example.test", 1)}, "references"),
        ({"falsepositives": ("known", 1)}, "falsepositives"),
    ],
)
def test_sigma_validation_checks_spec_boundary(kwargs: dict[str, object], message: str) -> None:
    defaults: dict[str, object] = {
        "title": "Valid rule",
        "logsource": {"category": "process_creation"},
        "detection": {"selection": {"EventID": 1}, "condition": "selection"},
    }
    defaults.update(kwargs)

    with pytest.raises(ValueError, match=message):
        SigmaRule(**defaults)
