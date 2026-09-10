from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from threat_to_detection.cli import select_cves_command
from threat_to_detection.models.vulnerability import Vulnerability
from threat_to_detection.services.cve_selection import (
    CATEGORIES,
    InsufficientCandidatesError,
    iter_date_windows,
    replay_selection,
    select_cves,
)


def _candidates(per_category: int = 8) -> tuple[Vulnerability, ...]:
    products = {
        "os_system_foundation": "linux_kernel",
        "web_application_foundation": "apache_http_server",
        "network_security_appliance": "cisco_asa",
        "client_endpoint": "google_chrome",
        "database_data_platform": "postgresql",
        "cloud_virtualization_container": "kubernetes",
        "iot_embedded_ot_ics": "scada_controller",
    }
    vulnerabilities: list[Vulnerability] = []
    for category_index, category in enumerate(CATEGORIES):
        for item in range(per_category):
            vulnerabilities.append(
                Vulnerability(
                    cve_id=f"CVE-202{1 + item % 5}-{category_index:02d}{item:04d}",
                    vendor="fixture-vendor",
                    product=products[category],
                    published=f"202{1 + item % 5}-02-01T00:00:00.000Z",
                    cwes=("CWE-79",) if item % 2 else (),
                )
            )
    return tuple(vulnerabilities)


def test_selection_is_seeded_and_independent_of_mapping_fields() -> None:
    original = _candidates()
    changed = tuple(item.model_copy(update={"cwes": ("CWE-89",)}) for item in reversed(original))

    first = select_cves(original, seed=23)
    second = select_cves(changed, seed=23)

    assert len(first.selected) == 42
    assert {item["category"] for item in first.selected} == set(CATEGORIES)
    assert all(
        sum(item["selected"] for item in first.candidates if item["category"] == category) == 6
        for category in CATEGORIES
    )
    assert [item["cve_id"] for item in first.selected] == [
        item["cve_id"] for item in second.selected
    ]
    assert first.to_mapping()["selection"]["seed"] == 23


def test_rejected_and_out_of_period_cves_are_excluded() -> None:
    candidates = list(_candidates())
    candidates.extend(
        [
            candidates[0].model_copy(
                update={"cve_id": "CVE-2020-0001", "published": "2020-12-31T23:59:59Z"}
            ),
            candidates[0].model_copy(
                update={
                    "cve_id": "CVE-2022-REJECTED",
                    "published": "2022-01-01T00:00:00Z",
                    "vuln_status": "Rejected",
                }
            ),
        ]
    )

    result = select_cves(candidates)

    assert result.exclusions["outside_publication_period"] == 1
    assert result.exclusions["rejected"] == 1
    assert "CVE-2020-0001" not in {item["cve_id"] for item in result.candidates}
    assert "CVE-2022-REJECTED" not in {item["cve_id"] for item in result.candidates}


def test_selection_fails_when_a_category_has_too_few_candidates() -> None:
    with pytest.raises(InsufficientCandidatesError, match="per category"):
        select_cves(_candidates(per_category=5))


def test_date_windows_cover_period_without_overlap() -> None:
    windows = iter_date_windows(date(2021, 1, 1), date(2021, 12, 31), window_days=90)

    assert windows[0] == ("2021-01-01T00:00:00.000", "2021-03-31T23:59:59.999")
    assert windows[-1][1] == "2021-12-31T23:59:59.999"
    assert [window[0][:10] for window in windows[1:]] == [
        "2021-04-01",
        "2021-06-30",
        "2021-09-28",
        "2021-12-27",
    ]


def test_select_command_writes_machine_readable_result(tmp_path: Path) -> None:
    fixture = tmp_path / "nvd.json"
    fixture.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": item.cve_id,
                            "published": item.published,
                            "vulnStatus": item.vuln_status or "Analyzed",
                            "descriptions": [{"lang": "en", "value": item.description}],
                            "configurations": [
                                {
                                    "nodes": [
                                        {
                                            "cpeMatch": [
                                                {
                                                    "criteria": (
                                                        f"cpe:2.3:a:{item.vendor}:"
                                                        f"{item.product}:1.0:*:*:*:*:*:*:*"
                                                    )
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    }
                    for item in _candidates()
                ]
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "selection.json"

    assert (
        select_cves_command(
            [
                "--nvd-fixture",
                str(fixture),
                "--offline",
                "--output",
                str(output),
            ]
        )
        == 0
    )

    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["counts"]["selected_records"] == 42
    assert set(document["candidate_sets"]) == set(CATEGORIES)
    assert document["selection"]["mapping_independence"]
    assert all("cwes" in item for item in document["selected"])
    assert all(
        "cwes" not in item
        for records in document["candidate_sets"].values()
        for item in records
    )


def test_selection_can_be_replayed_without_nvd_input(tmp_path: Path) -> None:
    selection = select_cves(_candidates()).to_mapping()
    source = tmp_path / "selection.json"
    source.write_text(json.dumps(selection), encoding="utf-8")

    replayed = replay_selection(source)

    assert replayed["selected"] == selection["selected"]


def test_replay_rejects_inconsistent_selected_flags(tmp_path: Path) -> None:
    selection = select_cves(_candidates()).to_mapping()
    selection["selected"][0]["cve_id"] = "CVE-NOT-IN-CANDIDATES"
    source = tmp_path / "selection.json"
    source.write_text(json.dumps(selection), encoding="utf-8")

    with pytest.raises(ValueError, match="selected and candidate_sets"):
        replay_selection(source)


def test_select_command_replays_committed_result_offline(tmp_path: Path) -> None:
    source = tmp_path / "selection.json"
    source.write_text(json.dumps(select_cves(_candidates()).to_mapping()), encoding="utf-8")
    output = tmp_path / "replayed.json"

    assert select_cves_command(
        ["--offline", "--replay", str(source), "--output", str(output)]
    ) == 0
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["source"]["mode"] == "replay"
    assert document["selected"] == json.loads(source.read_text(encoding="utf-8"))["selected"]
