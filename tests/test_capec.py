from pathlib import Path

from threat_to_detection.collectors.capec import CapecDataset
from threat_to_detection.mappers.cwe_to_capec import map_cwe_to_capec, map_cwes_to_capec


FIXTURE = Path(__file__).parent / "fixtures/capec/attack_patterns.xml"


def test_capec_xml_is_normalized_and_indexed_by_cwe() -> None:
    dataset = CapecDataset.from_xml(FIXTURE)

    patterns = map_cwe_to_capec("CWE-79", dataset)
    assert [pattern.capec_id for pattern in patterns] == ["CAPEC-100", "CAPEC-101"]
    assert patterns[0].related_weaknesses == ("CWE-79", "CWE-89")
    assert patterns[0].description == "An example attack pattern."


def test_cwe_mapping_supports_zero_and_one_match() -> None:
    dataset = CapecDataset.from_xml(FIXTURE)
    result = map_cwes_to_capec(("CWE-79", "CWE-89", "CWE-999"), dataset)

    assert len(result["CWE-79"]) == 2
    assert [pattern.capec_id for pattern in result["CWE-89"]] == ["CAPEC-100"]
    assert result["CWE-999"] == ()
