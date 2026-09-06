from pathlib import Path

from threat_to_detection.collectors.attack import AttackDataset
from threat_to_detection.mappers.capec_to_attack import map_capec_to_attack


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
