"""CWE to CAPEC reverse mapping."""

from threat_to_detection.collectors.capec import CapecDataset
from threat_to_detection.models.capec import CapecAttackPattern


def map_cwe_to_capec(cwe_id: str, dataset: CapecDataset) -> tuple[CapecAttackPattern, ...]:
    """Return all CAPEC candidates related to a CWE ID."""
    return dataset.for_cwe(cwe_id)


def map_cwes_to_capec(
    cwe_ids: tuple[str, ...], dataset: CapecDataset
) -> dict[str, tuple[CapecAttackPattern, ...]]:
    """Map multiple CWE IDs while preserving zero-, one-, and many-match cases."""
    return {cwe_id: map_cwe_to_capec(cwe_id, dataset) for cwe_id in cwe_ids}
