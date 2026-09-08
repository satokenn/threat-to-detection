from __future__ import annotations

import json
from pathlib import Path

from threat_to_detection.cli import analyze_scenario
from threat_to_detection.collectors.nvd import NvdClient


ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def _run_fixture_analysis(output_dir: Path) -> dict:
    assert (
        analyze_scenario(
            [
                str(ROOT / "evaluations" / "scenario.yaml"),
                "--nvd-fixture",
                str(FIXTURES / "nvd" / "cves.json"),
                "--capec-fixture",
                str(FIXTURES / "capec" / "attack_patterns.xml"),
                "--attack-fixture",
                str(FIXTURES / "attack" / "enterprise-attack.json"),
                "--offline",
                "--output-dir",
                str(output_dir),
            ]
        )
        == 0
    )
    return json.loads((output_dir / "analysis.json").read_text(encoding="utf-8"))


def test_fixture_output_contract_is_machine_readable(tmp_path: Path) -> None:
    document = _run_fixture_analysis(tmp_path / "output")

    assert document["schema_version"] == "1.0"
    assert document["status"] == "partial"
    assert document["mode"] == "fixture"
    assert isinstance(document["mapping_gaps"], list)
    assert isinstance(document["warnings"], list)
    assert isinstance(document["errors"], list)
    assert set(document["snapshots"]) == {"nvd", "capec", "attack"}
    for snapshot in document["snapshots"].values():
        assert snapshot["mode"] == "fixture"
        assert snapshot["url"]
        assert snapshot["release"]
        assert snapshot["sha"]
        assert len(snapshot["raw_sha256"]) == 64
        assert snapshot["normalization"]
        assert snapshot["exclusions"]

    assert document["metrics"] == {
        "assets": 2,
        "cves": 1,
        "cwes": 1,
        "capecs": 2,
        "techniques": 2,
        "detection_requirements": 1,
        "sigma_rules": 1,
        "complete_paths": 1,
        "candidate_paths": 1,
        "mapping_gaps": 2,
        "positive_samples": 1,
        "positive_matched": 1,
        "negative_samples": 1,
        "negative_matched": 0,
        "errors": 0,
    }
    assert document["evaluation"]["status"] == "pass"
    assert document["evaluation"]["positive"]["result"] == "pass"
    assert document["evaluation"]["negative"]["result"] == "pass"
    rule = document["assets"]["web-server"]["sigma_rules"][0]
    assert rule["rule_kind"] == "detection_candidate"
    assert {"title", "logsource", "detection", "id"} <= set(rule["mapping"])


def test_manifest_links_inputs_to_every_owned_artifact(tmp_path: Path) -> None:
    output_dir = tmp_path / "output"
    _run_fixture_analysis(output_dir)
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["inputs"]["scenario"]["sha256"]
    assert set(manifest["inputs"]["snapshots"]) == {"nvd", "capec", "attack"}
    assert manifest["files"][0]["path"] == "analysis.json"
    for item in manifest["files"]:
        assert item["status"] in {"generated", "written", "write_failed", "generation_failed"}
        assert item["depends_on"]
        if item["path"]:
            assert item["sha256"]
    assert {item["artifact"] for item in manifest["relationships"]} == {
        item["path"] for item in manifest["files"]
    }


def test_analyze_default_is_network_free(tmp_path: Path, monkeypatch) -> None:
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("system:\n  assets:\n    - name: empty\n", encoding="utf-8")
    nvd_cache = tmp_path / "nvd-cache"
    capec_path = tmp_path / "missing.xml"
    attack_path = tmp_path / "missing.json"
    calls = 0

    def forbidden_network(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("default analyze must not access the network")

    monkeypatch.setattr("threat_to_detection.collectors.nvd.urlopen", forbidden_network)
    monkeypatch.setattr("threat_to_detection.collectors.capec.urlopen", forbidden_network)
    monkeypatch.setattr("threat_to_detection.collectors.attack.urlopen", forbidden_network)

    assert (
        analyze_scenario(
            [
                str(scenario),
                "--nvd-cache",
                str(nvd_cache),
                "--capec-path",
                str(capec_path),
                "--attack-path",
                str(attack_path),
                "--output-dir",
                str(tmp_path / "output"),
            ]
        )
        == 0
    )
    assert calls == 0


def test_nvd_cache_and_refresh_modes_are_distinguishable(tmp_path: Path) -> None:
    payload = {"vulnerabilities": []}
    calls = 0

    def opener(_request, _timeout):
        nonlocal calls
        calls += 1
        return payload

    query = {"cve_id": "CVE-TEST-0001"}
    online = NvdClient(cache_dir=tmp_path, opener=opener)
    online.search_cves(**query)
    assert online.request_metadata[0]["mode"] == "online"

    cached = NvdClient(cache_dir=tmp_path, allow_network=False)
    cached.search_cves(**query)
    assert cached.request_metadata[0]["mode"] == "cache"

    refreshed = NvdClient(cache_dir=tmp_path, opener=opener, refresh=True)
    refreshed.search_cves(**query)
    assert refreshed.request_metadata[0]["mode"] == "refresh"
    assert calls == 2


def test_offline_analyze_reads_an_existing_nvd_cache(tmp_path: Path) -> None:
    fixture_path = FIXTURES / "nvd" / "cves.json"
    payload = json.loads(fixture_path.read_text(encoding="utf-8"))
    cache_dir = tmp_path / "nvd-cache"
    client = NvdClient(cache_dir=cache_dir, opener=lambda _request, _timeout: payload)
    client.search_cves(
        cpe_name="cpe:2.3:a:vendor:example-product:1.0:*:*:*:*:*:*:*"
    )

    output_dir = tmp_path / "output"
    assert (
        analyze_scenario(
            [
                str(ROOT / "evaluations" / "scenario.yaml"),
                "--offline",
                "--nvd-cache",
                str(cache_dir),
                "--capec-fixture",
                str(FIXTURES / "capec" / "attack_patterns.xml"),
                "--attack-fixture",
                str(FIXTURES / "attack" / "enterprise-attack.json"),
                "--output-dir",
                str(output_dir),
            ]
        )
        == 0
    )
    document = json.loads((output_dir / "analysis.json").read_text(encoding="utf-8"))
    assert document["snapshots"]["nvd"]["mode"] == "cache"
    assert document["assets"]["web-server"]["vulnerabilities"]
