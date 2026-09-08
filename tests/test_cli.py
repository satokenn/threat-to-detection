from __future__ import annotations

import json
from pathlib import Path

import yaml

from threat_to_detection.cli import analyze_scenario, build_analyze_parser


def test_analyze_defaults_to_output_artifact_root() -> None:
    assert build_analyze_parser().parse_args(["scenario.yaml"]).output_dir == "output"


def test_offline_without_nvd_fixture_never_constructs_network_client(
    tmp_path: Path, monkeypatch
) -> None:
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text(
        "system:\n"
        "  assets:\n"
        "    - name: web\n"
        "      software:\n"
        "        - product: example-product\n"
        "          version: '1.0'\n",
        encoding="utf-8",
    )
    fixtures = Path(__file__).parent / "fixtures"

    def forbidden_network_client(*_args, **_kwargs):
        raise AssertionError("NVD client must not be constructed in offline mode")

    monkeypatch.setattr("threat_to_detection.cli.NvdClient", forbidden_network_client)
    output_dir = tmp_path / "out"
    assert (
        analyze_scenario(
            [
                str(scenario),
                "--offline",
                "--capec-fixture",
                str(fixtures / "capec/attack_patterns.xml"),
                "--attack-fixture",
                str(fixtures / "attack/enterprise-attack.json"),
                "--output-dir",
                str(output_dir),
            ]
        )
        == 0
    )
    document = json.loads((output_dir / "analysis.json").read_text(encoding="utf-8"))
    assert document["status"] == "partial"
    assert document["schema_version"] == "1.0"
    assert (output_dir / "manifest.json").is_file()
    assert any(
        error["stage"] == "nvd" and "network access is disabled" in error["message"]
        for error in document["errors"]
    )


def test_analyze_cli_runs_offline_fixture_end_to_end(tmp_path: Path) -> None:
    fixtures = Path(__file__).parent / "fixtures"
    output_dir = tmp_path / "artifacts"

    status = analyze_scenario(
        [
            str(Path(__file__).parents[1] / "examples/web-system.yaml"),
            "--nvd-fixture",
            str(fixtures / "nvd/cves.json"),
            "--capec-fixture",
            str(fixtures / "capec/attack_patterns.xml"),
            "--attack-fixture",
            str(fixtures / "attack/enterprise-attack.json"),
            "--offline",
            "--output-dir",
            str(output_dir),
            "--logsource-category",
            "dns",
        ]
    )

    assert status == 0
    document = json.loads((output_dir / "analysis.json").read_text(encoding="utf-8"))
    assert document["system"]["assets"][0]["software"][0]["cpe_name"].startswith("cpe:2.3:")
    assert document["trace_paths"][0]["cve_id"] == "CVE-TEST-0001"
    sigma_files = list((output_dir / "sigma").glob("*.yml"))
    assert len(sigma_files) == 1
    sigma = yaml.safe_load(sigma_files[0].read_text(encoding="utf-8"))
    assert sigma["logsource"] == {"category": "dns"}
    assert sigma["id"]
    assert sigma["x_threat_to_detection"]["rule_kind"] == "detection_candidate"
    assert sigma["x_threat_to_detection"]["capec_ids"] == ["CAPEC-100"]
    assert sigma["x_threat_to_detection"]["provenance"][0]["source_id"].startswith(
        "web-server:CVE-TEST-0001:"
    )


def test_analyze_cli_keeps_partial_results_when_datasets_are_missing(tmp_path: Path) -> None:
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("system:\n  assets:\n    - name: empty\n", encoding="utf-8")

    status = analyze_scenario(
        [str(scenario), "--offline", "--output-dir", str(tmp_path / "out")]
    )

    assert status == 0
    document = json.loads((tmp_path / "out/analysis.json").read_text(encoding="utf-8"))
    assert "capec" in {error["stage"] for error in document["errors"]}
    assert document["assets"]["empty"]["vulnerabilities"] == []


def test_analyze_records_sigma_failure_without_losing_requirement(tmp_path: Path) -> None:
    from threat_to_detection.collectors.attack import AttackDataset
    from threat_to_detection.collectors.capec import CapecDataset
    from threat_to_detection.models.system import Asset, Software, SystemModel
    from threat_to_detection.models.vulnerability import Vulnerability
    from threat_to_detection.services.pipeline import run_analysis

    fixtures = Path(__file__).parent / "fixtures"
    system = SystemModel(
        assets=(
            Asset(
                name="web",
                software=(Software(product="example-product", version="1.0"),),
            ),
        )
    )
    result = run_analysis(
        system,
        vulnerabilities=(
            Vulnerability(
                cve_id="CVE-TEST-0001",
                product="example-product",
                affected_versions=("1.0",),
                cwes=("CWE-79",),
            ),
        ),
        capec_dataset=CapecDataset.from_xml(fixtures / "capec/attack_patterns.xml"),
        attack_dataset=AttackDataset.from_json(fixtures / "attack/enterprise-attack.json"),
        sigma_generator=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("fixture render failure")
        ),
        output_dir=tmp_path,
    )

    assert result.detection_requirements["web"]
    assert result.sigma_rules["web"] == ()
    assert result.errors[0].requirement_id == "DET0001"


def test_mapping_gaps_and_intermediate_ids_are_retained() -> None:
    from threat_to_detection.collectors.attack import AttackDataset
    from threat_to_detection.collectors.capec import CapecDataset
    from threat_to_detection.models.system import Asset, Software, SystemModel
    from threat_to_detection.models.vulnerability import Vulnerability
    from threat_to_detection.services.pipeline import run_analysis

    fixtures = Path(__file__).parent / "fixtures"
    system = SystemModel(
        assets=(
            Asset(name="web", software=(Software(product="example-product", version="1.0"),)),
        )
    )
    vulnerabilities = (
        Vulnerability(
            cve_id="CVE-NO-CWE",
            product="example-product",
            affected_versions=("1.0",),
        ),
        Vulnerability(
            cve_id="CVE-UNKNOWN-CWE",
            product="example-product",
            affected_versions=("1.0",),
            cwes=("CWE-999",),
        ),
        Vulnerability(
            cve_id="CVE-PARTIAL",
            product="example-product",
            affected_versions=("1.0",),
            cwes=("CWE-79",),
        ),
    )
    result = run_analysis(
        system,
        vulnerabilities=vulnerabilities,
        capec_dataset=CapecDataset.from_xml(fixtures / "capec/attack_patterns.xml"),
        attack_dataset=AttackDataset.from_json(fixtures / "attack/enterprise-attack.json"),
    )
    mapping = result.to_mapping(system)
    stages = {gap["stage"] for gap in mapping["mapping_gaps"]}
    assert {"CVE→CWE", "CWE→CAPEC", "CAPEC→ATT&CK", "Technique→Requirement"} <= stages
    assert mapping["assets"]["web"]["intermediate"]["cwe_ids"] == [
        "CWE-999",
        "CWE-79",
    ]
    assert "CAPEC-100" in mapping["assets"]["web"]["intermediate"]["capec_ids"]
    assert "T1059" in mapping["assets"]["web"]["intermediate"]["technique_ids"]


def test_provider_asset_attribution_is_not_redistributed() -> None:
    from threat_to_detection.models.system import Asset, Software, SystemModel
    from threat_to_detection.models.vulnerability import Vulnerability
    from threat_to_detection.services.pipeline import run_analysis

    software = Software(product="example-product", version="1.0")
    system = SystemModel(
        assets=(Asset(name="one", software=(software,)), Asset(name="two", software=(software,)))
    )
    vulnerability = Vulnerability(
        cve_id="CVE-ONE",
        product="example-product",
        affected_versions=("1.0",),
    )
    result = run_analysis(
        system,
        vulnerability_provider=lambda _system: {"one": (vulnerability,), "two": ()},
    )

    assert [item.cve_id for item in result.relevant_vulnerabilities["one"]] == ["CVE-ONE"]
    assert result.relevant_vulnerabilities["two"] == ()


def test_run_pipeline_nvd_client_keeps_per_asset_fetch_results() -> None:
    from threat_to_detection.models.system import Asset, Software, SystemModel
    from threat_to_detection.models.vulnerability import Vulnerability
    from threat_to_detection.services.pipeline import run_pipeline

    software = Software(product="example-product", version="1.0")
    system = SystemModel(
        assets=(Asset(name="one", software=(software,)), Asset(name="two", software=(software,)))
    )
    vulnerability = Vulnerability(
        cve_id="CVE-ONE", product="example-product", affected_versions=("1.0",)
    )

    class Provider:
        def __init__(self) -> None:
            self.calls = 0

        def search_for_software(self, _software: Software) -> tuple[Vulnerability, ...]:
            self.calls += 1
            return (vulnerability,) if self.calls == 1 else ()

    provider = Provider()
    result = run_pipeline(system, nvd_client=provider)  # type: ignore[arg-type]
    assert result.relevant_vulnerabilities["one"] == (vulnerability,)
    assert result.relevant_vulnerabilities["two"] == ()
    assert provider.calls == 2


def test_system_rejects_duplicate_asset_names() -> None:
    import pytest

    from threat_to_detection.models.system import Asset, SystemModel

    with pytest.raises(ValueError, match="unique"):
        SystemModel(assets=(Asset(name="same"), Asset(name="same")))


def test_logsource_resolver_and_write_status_are_explicit(tmp_path: Path) -> None:
    from threat_to_detection.collectors.attack import AttackDataset
    from threat_to_detection.collectors.capec import CapecDataset
    from threat_to_detection.models.system import Asset, Software, SystemModel
    from threat_to_detection.models.vulnerability import Vulnerability
    from threat_to_detection.services.pipeline import run_analysis

    fixtures = Path(__file__).parent / "fixtures"
    system = SystemModel(
        assets=(Asset(name="web", software=(Software(product="example-product", version="1.0"),)),)
    )
    vuln = Vulnerability(
        cve_id="CVE-TEST-0001",
        product="example-product",
        affected_versions=("1.0",),
        cwes=("CWE-79",),
    )
    result = run_analysis(
        system,
        vulnerabilities=(vuln,),
        capec_dataset=CapecDataset.from_xml(fixtures / "capec/attack_patterns.xml"),
        attack_dataset=AttackDataset.from_json(fixtures / "attack/enterprise-attack.json"),
        logsource_resolver=lambda _requirement: {"category": "dns"},
    )
    assert result.sigma_rules["web"][0].logsource == {"category": "dns"}
    assert result.sigma_artifacts["web"][0].status == "generated"
    assert result.sigma_artifacts["web"][0].file is None

    blocked = tmp_path / "not-a-directory"
    blocked.write_text("x", encoding="utf-8")
    failed = run_analysis(
        system,
        vulnerabilities=(vuln,),
        capec_dataset=CapecDataset.from_xml(fixtures / "capec/attack_patterns.xml"),
        attack_dataset=AttackDataset.from_json(fixtures / "attack/enterprise-attack.json"),
        output_dir=blocked,
    )
    assert failed.sigma_rules["web"]
    assert failed.sigma_artifacts["web"][0].status == "write_failed"
    assert failed.sigma_artifacts["web"][0].file is None


def test_logsource_resolver_internal_type_error_is_not_retried() -> None:
    from threat_to_detection.collectors.attack import AttackDataset
    from threat_to_detection.collectors.capec import CapecDataset
    from threat_to_detection.models.system import Asset, Software, SystemModel
    from threat_to_detection.models.vulnerability import Vulnerability
    from threat_to_detection.services.pipeline import run_analysis

    fixtures = Path(__file__).parent / "fixtures"
    system = SystemModel(
        assets=(Asset(name="web", software=(Software(product="example-product", version="1.0"),)),)
    )
    vuln = Vulnerability(
        cve_id="CVE-TEST-0001",
        product="example-product",
        affected_versions=("1.0",),
        cwes=("CWE-79",),
    )
    calls = 0

    def resolver(_requirement: object) -> dict[str, str]:
        nonlocal calls
        calls += 1
        raise TypeError("resolver implementation bug")

    result = run_analysis(
        system,
        vulnerabilities=(vuln,),
        capec_dataset=CapecDataset.from_xml(fixtures / "capec/attack_patterns.xml"),
        attack_dataset=AttackDataset.from_json(fixtures / "attack/enterprise-attack.json"),
        logsource_resolver=resolver,
    )
    assert calls == 1
    assert result.sigma_artifacts["web"][0].status == "generation_failed"
    assert "resolver implementation bug" in result.errors[0].message


def test_shared_strategy_identity_and_filename_hash_are_stable(tmp_path: Path) -> None:
    from threat_to_detection.collectors.attack import AttackDataset
    from threat_to_detection.collectors.capec import CapecDataset
    from threat_to_detection.models.attack import AttackTechnique
    from threat_to_detection.models.capec import CapecAttackPattern
    from threat_to_detection.models.detection import (
        DataComponent,
        DetectionAnalytic,
        DetectionRequirement,
    )
    from threat_to_detection.models.system import Asset, Software, SystemModel
    from threat_to_detection.models.vulnerability import Vulnerability
    from threat_to_detection.services.pipeline import run_analysis

    analytic = DetectionAnalytic(
        analytic_id="AN",
        name="process",
        data_components=(DataComponent(component_id="DC", name="Process Creation"),),
        events=("Event ID 1",),
    )
    requirements = {
        "T1001": (DetectionRequirement("T1001", "DET-SHARED", "Shared", (analytic,)),),
        "T1002": (DetectionRequirement("T1002", "DET-SHARED", "Shared", (analytic,)),),
    }
    attack = AttackDataset(
        (
            AttackTechnique(
                technique_id="T1001", name="one", related_capec_ids=("CAPEC-1",)
            ),
            AttackTechnique(
                technique_id="T1002", name="two", related_capec_ids=("CAPEC-1",)
            ),
        ),
        requirements,
    )
    capec = CapecDataset(
        (
            CapecAttackPattern(
                capec_id="CAPEC-1",
                name="pattern",
                related_weaknesses=("CWE-1",),
            ),
        )
    )
    software = Software(product="p", version="1")
    system = SystemModel(
        assets=(Asset(name="a/b", software=(software,)), Asset(name="a_b", software=(software,)))
    )
    vuln = Vulnerability(
        cve_id="CVE-1", product="p", affected_versions=("1",), cwes=("CWE-1",)
    )
    result = run_analysis(
        system,
        vulnerabilities=(vuln,),
        capec_dataset=capec,
        attack_dataset=attack,
        output_dir=tmp_path,
    )
    artifacts = [artifact for values in result.sigma_artifacts.values() for artifact in values]
    assert len(artifacts) == 4
    assert {artifact.technique_id for artifact in artifacts} == {"T1001", "T1002"}
    assert len({artifact.file for artifact in artifacts}) == 4
    assert all(artifact.status == "written" for artifact in artifacts)
    assert all((tmp_path / artifact.file).is_file() for artifact in artifacts if artifact.file)
