"""Application-level pipeline orchestration."""

from dataclasses import dataclass

from threat_to_detection.analyzers.relevance import find_relevant_vulnerabilities
from threat_to_detection.models.system import SystemModel
from threat_to_detection.models.vulnerability import Vulnerability


@dataclass(frozen=True)
class PipelineResult:
    relevant_vulnerabilities: dict[str, tuple[Vulnerability, ...]]


def run_pipeline(
    system: SystemModel, vulnerabilities: tuple[Vulnerability, ...] = ()
) -> PipelineResult:
    """Run the currently implemented stages of the analysis pipeline."""
    return PipelineResult(find_relevant_vulnerabilities(system, vulnerabilities))
