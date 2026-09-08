"""CAPEC to MITRE ATT&CK technique mapping."""

from threat_to_detection.collectors.attack import AttackDataset
from threat_to_detection.models.attack import AttackTechnique
from threat_to_detection.models.detection import DetectionRequirement


def map_capec_to_attack(
    capec_id: str, dataset: AttackDataset
) -> tuple[AttackTechnique, ...]:
    """Return all ATT&CK techniques related to a CAPEC ID."""
    return dataset.for_capec(capec_id)


def map_attack_to_detection(
    technique_id: str, dataset: AttackDataset
) -> tuple[DetectionRequirement, ...]:
    """Return normalized detection requirements for an ATT&CK technique."""
    return dataset.detection_requirements_for_technique(technique_id)
