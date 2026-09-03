"""Relevance analysis between system assets and normalized vulnerabilities."""

from threat_to_detection.models.system import SystemModel
from threat_to_detection.models.vulnerability import Vulnerability


def find_relevant_vulnerabilities(
    system: SystemModel, vulnerabilities: tuple[Vulnerability, ...]
) -> dict[str, tuple[Vulnerability, ...]]:
    """Return vulnerabilities matching an asset's software name and version.

    This deliberately uses exact matching for the MVP. CPE/range matching belongs
    in a later collector or matcher once representative fixtures are available.
    """
    result: dict[str, tuple[Vulnerability, ...]] = {}
    for asset in system.assets:
        matches = tuple(
            vulnerability
            for vulnerability in vulnerabilities
            if any(
                software.name == vulnerability.product
                and software.version in vulnerability.affected_versions
                for software in asset.software
            )
        )
        result[asset.name] = matches
    return result
