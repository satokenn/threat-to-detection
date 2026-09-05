"""CAPEC to MITRE ATT&CK technique mapping."""

from threat_to_detection.collectors.attack import AttackDataset
from threat_to_detection.models.attack import AttackTechnique


def map_capec_to_attack(
    capec_id: str, dataset: AttackDataset
) -> tuple[AttackTechnique, ...]:
    """Return all ATT&CK techniques related to a CAPEC ID."""
    return dataset.for_capec(capec_id)
