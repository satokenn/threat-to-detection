"""Application-level pipeline orchestration.

``run_pipeline`` remains the small, backwards-compatible mapping API used by
the earlier days of the project.  ``run_analysis`` is the end-to-end entry
point: it optionally obtains vulnerabilities, maps every CVE/CWE/CAPEC/ATT&CK
edge, and renders Sigma rules while retaining the individual paths.
"""

import hashlib
import inspect
import logging
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from threat_to_detection.analyzers.relevance import find_relevant_vulnerabilities
from threat_to_detection.collectors.attack import AttackDataset
from threat_to_detection.collectors.capec import CapecDataset
from threat_to_detection.collectors.nvd import NvdClient
from threat_to_detection.mappers.capec_to_attack import (
    map_attack_to_detection,
    map_capec_to_attack,
)
from threat_to_detection.mappers.cwe_to_capec import map_cwe_to_capec
from threat_to_detection.models.detection import DetectionRequirement
from threat_to_detection.models.sigma import SigmaEvidence, SigmaEvidenceRecord, SigmaRule
from threat_to_detection.models.system import SystemModel
from threat_to_detection.models.vulnerability import Vulnerability
from threat_to_detection.reporters.sigma import (
    detection_requirement_to_sigma,
    logsource_for_detection_requirement,
    render_sigma_yaml,
)

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class PipelineResult:
    relevant_vulnerabilities: dict[str, tuple[Vulnerability, ...]]
    detection_requirements: dict[str, tuple[DetectionRequirement, ...]] = field(
        default_factory=dict
    )
    traces: tuple["TracePath", ...] = ()
    sigma_rules: dict[str, tuple[SigmaRule, ...]] = field(default_factory=dict)
    errors: tuple["PipelineError", ...] = ()
    mapping_gaps: tuple["MappingGap", ...] = ()
    intermediates: dict[str, dict[str, tuple[str, ...]]] = field(default_factory=dict)
    sigma_artifacts: dict[str, tuple["SigmaArtifact", ...]] = field(default_factory=dict)
    scenario_id: str = "scenario"

    @property
    def trace_paths(self) -> tuple["TracePath", ...]:
        """Explicit alias for callers that prefer the report terminology."""
        return self.traces

    @property
    def status(self) -> str:
        return "partial" if self.errors or self.mapping_gaps else "success"

    def to_mapping(self, system: SystemModel | None = None) -> dict[str, Any]:
        """Return a JSON-safe representation of all intermediate results."""
        assets: dict[str, Any] = {}
        asset_names = list(self.relevant_vulnerabilities)
        for asset in asset_names:
            asset_traces = [trace for trace in self.traces if trace.asset == asset]
            assets[asset] = {
                "vulnerabilities": [
                    _vulnerability_mapping(item)
                    for item in self.relevant_vulnerabilities.get(asset, ())
                ],
                "detection_requirements": [
                    _requirement_mapping(item)
                    for item in self.detection_requirements.get(asset, ())
                ],
                "trace_paths": [trace.to_mapping() for trace in asset_traces],
                "intermediate": {
                    key: list(values)
                    for key, values in self.intermediates.get(asset, {}).items()
                },
                "mapping_gaps": [
                    gap.to_mapping() for gap in self.mapping_gaps if gap.asset == asset
                ],
                "sigma_rules": [
                    {
                        "file": _artifact_for_rule(self, asset, rule).file
                        if _artifact_for_rule(self, asset, rule)
                        else None,
                        "status": _artifact_for_rule(self, asset, rule).status
                        if _artifact_for_rule(self, asset, rule)
                        else "generated",
                        "title": rule.title,
                        "rule_id": rule.rule_id,
                        "rule_kind": rule.rule_kind,
                        "technique_id": _technique_from_rule(rule),
                        "mapping": rule.to_mapping(),
                    }
                    for rule in self.sigma_rules.get(asset, ())
                ],
                "sigma_artifacts": [
                    artifact.to_mapping()
                    for artifact in self.sigma_artifacts.get(asset, ())
                ],
                "errors": [error.to_mapping() for error in self.errors if error.asset == asset],
            }
        result: dict[str, Any] = {
            "schema_version": "1.0",
            "scenario_id": self.scenario_id,
            "assets": assets,
            "trace_paths": [trace.to_mapping() for trace in self.traces],
            "mapping_gaps": [gap.to_mapping() for gap in self.mapping_gaps],
            "intermediate": {
                asset: {
                    key: list(values) for key, values in data.items()
                }
                for asset, data in self.intermediates.items()
            },
            "errors": [error.to_mapping() for error in self.errors],
            "warnings": [],
            "sigma_artifacts": {
                asset: [artifact.to_mapping() for artifact in artifacts]
                for asset, artifacts in self.sigma_artifacts.items()
            },
            "status": self.status,
        }
        if system is not None:
            result["system"] = _system_mapping(system)
            result["threat_analysis"] = _threat_analysis_mapping(self, system)
            if system.scenario_type == "control":
                result["analysis_outcome"] = "control"
            elif self.traces or any(self.detection_requirements.values()):
                result["analysis_outcome"] = "matched"
            else:
                result["analysis_outcome"] = "no_match"
        return result


@dataclass(frozen=True)
class TracePath:
    """One complete CVE → CWE → CAPEC → technique → requirement path."""

    asset: str
    cve_id: str
    cwe_id: str
    capec_id: str
    technique_id: str
    strategy_id: str
    strategy_name: str = ""

    @property
    def path_id(self) -> str:
        return ":".join(
            (
                self.asset,
                self.cve_id,
                self.cwe_id,
                self.capec_id,
                self.technique_id,
                self.strategy_id,
            )
        )

    def to_mapping(self) -> dict[str, str]:
        return {
            "path_id": self.path_id,
            "asset": self.asset,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "capec_id": self.capec_id,
            "technique_id": self.technique_id,
            "strategy_id": self.strategy_id,
            "strategy_name": self.strategy_name,
        }


@dataclass(frozen=True)
class MappingGap:
    """A missing edge in the knowledge graph, retained with its context."""

    asset: str
    source: str
    path: str
    stage: str
    reason: str

    def to_mapping(self) -> dict[str, str]:
        return {
            "asset": self.asset,
            "source": self.source,
            "path": self.path,
            "stage": self.stage,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class SigmaArtifact:
    """A generated Sigma rule and the state of its optional file output."""

    asset: str
    technique_id: str
    requirement_id: str
    status: str
    file: str | None = None
    title: str = ""

    def to_mapping(self) -> dict[str, str | None]:
        return {
            "asset": self.asset,
            "technique_id": self.technique_id,
            "requirement_id": self.requirement_id,
            "status": self.status,
            "file": self.file,
            "title": self.title,
        }


@dataclass(frozen=True)
class PipelineError:
    """A recoverable stage error; one failed edge must not abort the run."""

    stage: str
    message: str
    asset: str | None = None
    requirement_id: str | None = None

    def to_mapping(self) -> dict[str, str]:
        result = {"stage": self.stage, "message": self.message}
        if self.asset:
            result["asset"] = self.asset
        if self.requirement_id:
            result["requirement_id"] = self.requirement_id
        return result


def run_pipeline(
    system: SystemModel,
    vulnerabilities: tuple[Vulnerability, ...] = (),
    *,
    capec_dataset: CapecDataset | None = None,
    attack_dataset: AttackDataset | None = None,
    nvd_client: NvdClient | None = None,
    asset_vulnerabilities: Mapping[str, tuple[Vulnerability, ...]] | None = None,
) -> PipelineResult:
    """Run the currently implemented stages of the analysis pipeline."""
    if nvd_client is not None and not vulnerabilities:
        asset_vulnerabilities = {}
        for asset in system.assets:
            fetched: dict[str, Vulnerability] = {}
            for software in asset.software:
                fetched.update(
                    {item.cve_id: item for item in nvd_client.search_for_software(software)}
                )
            asset_vulnerabilities[asset.name] = tuple(fetched.values())
    if asset_vulnerabilities is None:
        relevant = find_relevant_vulnerabilities(system, vulnerabilities)
    else:
        relevant = _filter_asset_vulnerabilities(system, asset_vulnerabilities)
    requirements: dict[str, tuple[DetectionRequirement, ...]] = {
        asset: () for asset in relevant
    }
    traces: list[TracePath] = []
    gaps: list[MappingGap] = []
    intermediate: dict[str, dict[str, tuple[str, ...]]] = {
        asset: {"cwe_ids": (), "capec_ids": (), "technique_ids": ()}
        for asset in relevant
    }
    if not capec_dataset or not attack_dataset:
        # A missing dataset is reported separately below; keep edge-level
        # context too so analysis remains useful with partial caches.
        for asset, values in relevant.items():
            for vulnerability in values:
                if not vulnerability.cwes:
                    gaps.append(
                        MappingGap(
                            asset,
                            vulnerability.cve_id,
                            vulnerability.cve_id,
                            "CVE→CWE",
                            "CVE has no CWE",
                        )
                    )
                for cwe_id in vulnerability.cwes:
                    intermediate[asset]["cwe_ids"] = _append_unique(
                        intermediate[asset]["cwe_ids"], cwe_id
                    )
                    if not capec_dataset:
                        gaps.append(
                            MappingGap(
                                asset,
                                cwe_id,
                                f"{vulnerability.cve_id}:{cwe_id}",
                                "CWE→CAPEC",
                                "CAPEC dataset unavailable",
                            )
                        )
                    elif not attack_dataset:
                        patterns = map_cwe_to_capec(cwe_id, capec_dataset)
                        if not patterns:
                            gaps.append(
                                MappingGap(
                                    asset,
                                    cwe_id,
                                    f"{vulnerability.cve_id}:{cwe_id}",
                                    "CWE→CAPEC",
                                    "No CAPEC pattern is mapped",
                                )
                            )
                        for pattern in patterns:
                            intermediate[asset]["capec_ids"] = _append_unique(
                                intermediate[asset]["capec_ids"], pattern.capec_id
                            )
                            gaps.append(
                                MappingGap(
                                    asset,
                                    pattern.capec_id,
                                    f"{vulnerability.cve_id}:{cwe_id}:{pattern.capec_id}",
                                    "CAPEC→ATT&CK",
                                    "ATT&CK dataset unavailable",
                                )
                            )
    if capec_dataset and attack_dataset:
        for asset, asset_vulnerabilities in relevant.items():
            # A strategy may be related to more than one technique. Keep both
            # edges in the result instead of collapsing them by strategy ID.
            mapped: dict[tuple[str, str], DetectionRequirement] = {}
            for vulnerability in asset_vulnerabilities:
                if not vulnerability.cwes:
                    gaps.append(
                        MappingGap(
                            asset,
                            vulnerability.cve_id,
                            vulnerability.cve_id,
                            "CVE→CWE",
                            "CVE has no CWE",
                        )
                    )
                for cwe_id in vulnerability.cwes:
                    intermediate[asset]["cwe_ids"] = _append_unique(
                        intermediate[asset]["cwe_ids"], cwe_id
                    )
                    patterns = map_cwe_to_capec(cwe_id, capec_dataset)
                    if not patterns:
                        gaps.append(
                            MappingGap(
                                asset,
                                cwe_id,
                                f"{vulnerability.cve_id}:{cwe_id}",
                                "CWE→CAPEC",
                                "No CAPEC pattern is mapped",
                            )
                        )
                    for pattern in patterns:
                        intermediate[asset]["capec_ids"] = _append_unique(
                            intermediate[asset]["capec_ids"], pattern.capec_id
                        )
                        techniques = map_capec_to_attack(pattern.capec_id, attack_dataset)
                        if not techniques:
                            gaps.append(
                                MappingGap(
                                    asset,
                                    pattern.capec_id,
                                    f"{vulnerability.cve_id}:{cwe_id}:{pattern.capec_id}",
                                    "CAPEC→ATT&CK",
                                    "No ATT&CK technique is mapped",
                                )
                            )
                        for technique in techniques:
                            intermediate[asset]["technique_ids"] = _append_unique(
                                intermediate[asset]["technique_ids"], technique.technique_id
                            )
                            requirements_for_technique = map_attack_to_detection(
                                technique.technique_id, attack_dataset
                            )
                            if not requirements_for_technique:
                                path = (
                                    f"{vulnerability.cve_id}:{cwe_id}:"
                                    f"{pattern.capec_id}:{technique.technique_id}"
                                )
                                gaps.append(
                                    MappingGap(
                                        asset,
                                        technique.technique_id,
                                        path,
                                        "Technique→Requirement",
                                        "No detection requirement is mapped",
                                    )
                                )
                            for requirement in requirements_for_technique:
                                mapped[
                                    (requirement.technique_id, requirement.strategy_id)
                                ] = requirement
                                trace = TracePath(
                                    asset=asset,
                                    cve_id=vulnerability.cve_id,
                                    cwe_id=cwe_id,
                                    capec_id=pattern.capec_id,
                                    technique_id=technique.technique_id,
                                    strategy_id=requirement.strategy_id,
                                    strategy_name=requirement.strategy_name,
                                )
                                if trace not in traces:
                                    traces.append(trace)
            requirements[asset] = tuple(mapped.values())
    # Non-CVE scenarios enter at the ATT&CK technique stage directly.  This
    # keeps malware/identity/network/cloud analyses on the same detection
    # requirement and Sigma path without inventing a CVE or CAPEC relation.
    if (
        attack_dataset
        and system.scenario.technique_ids
        and system.scenario_type != "control"
    ):
        for asset in relevant:
            mapped = {
                (item.technique_id, item.strategy_id): item
                for item in requirements.get(asset, ())
            }
            for technique_id in system.scenario.technique_ids:
                normalized = technique_id.strip().upper()
                requirements_for_technique = map_attack_to_detection(
                    normalized, attack_dataset
                )
                if not requirements_for_technique:
                    gaps.append(
                        MappingGap(
                            asset,
                            normalized,
                            f"{system.scenario.entrypoint_type}:{normalized}",
                            "Technique→Requirement",
                            "No detection requirement is mapped",
                        )
                    )
                    continue
                intermediate[asset]["technique_ids"] = _append_unique(
                    intermediate[asset]["technique_ids"], normalized
                )
                for requirement in requirements_for_technique:
                    mapped[(requirement.technique_id, requirement.strategy_id)] = requirement
                    trace = TracePath(
                        asset=asset,
                        cve_id="",
                        cwe_id="",
                        capec_id="",
                        technique_id=normalized,
                        strategy_id=requirement.strategy_id,
                        strategy_name=requirement.strategy_name,
                    )
                    if trace not in traces:
                        traces.append(trace)
            requirements[asset] = tuple(mapped.values())
    return PipelineResult(
        relevant,
        requirements,
        tuple(traces),
        mapping_gaps=tuple(_unique_gaps(gaps)),
        intermediates=intermediate,
    )


def run_analysis(
    system: SystemModel,
    vulnerabilities: tuple[Vulnerability, ...] | None = None,
    *,
    nvd_client: NvdClient | None = None,
    vulnerability_provider: Callable[[SystemModel], Mapping[str, tuple[Vulnerability, ...]]]
    | None = None,
    capec_dataset: CapecDataset | None = None,
    attack_dataset: AttackDataset | None = None,
    sigma_generator: Callable[..., SigmaRule] = detection_requirement_to_sigma,
    output_dir: str | Path | None = None,
    scenario_id: str | None = None,
    logsource_resolver: (
        Callable[..., Mapping[str, str]] | Mapping[str, Mapping[str, str]] | None
    ) = None,
) -> PipelineResult:
    """Run all available stages and optionally write Sigma files.

    Supplying ``vulnerabilities`` is useful for callers with their own source.
    Otherwise a provider or injectable :class:`NvdClient` is used.  Missing
    datasets and individual fetch/render errors are represented in ``errors``
    and do not discard successful assets or paths.
    """
    errors: list[PipelineError] = []
    scenario_id = scenario_id or _scenario_id(system)
    asset_vulnerabilities = None
    if vulnerabilities is None:
        vulnerabilities_by_asset = _fetch_vulnerabilities(
            system,
            nvd_client=nvd_client,
            vulnerability_provider=vulnerability_provider,
            errors=errors,
        )
        asset_vulnerabilities = vulnerabilities_by_asset
        vulnerabilities = ()
    result = run_pipeline(
        system,
        vulnerabilities,
        capec_dataset=capec_dataset,
        attack_dataset=attack_dataset,
        asset_vulnerabilities=asset_vulnerabilities,
    )
    has_vulnerability_input = any(result.relevant_vulnerabilities.values())
    if (
        not capec_dataset
        and not system.scenario.technique_ids
        and system.scenario_type != "control"
    ):
        errors.append(PipelineError("capec", "CAPEC dataset is unavailable"))
    if not attack_dataset and system.scenario_type != "control":
        errors.append(PipelineError("attack", "ATT&CK dataset is unavailable"))

    sigma_rules: dict[str, tuple[SigmaRule, ...]] = {
        asset: () for asset in result.relevant_vulnerabilities
    }
    sigma_artifacts: dict[str, tuple[SigmaArtifact, ...]] = {
        asset: () for asset in result.relevant_vulnerabilities
    }
    if attack_dataset and (capec_dataset or not has_vulnerability_input):
        for asset, requirements in result.detection_requirements.items():
            generated: list[SigmaRule] = []
            for requirement in requirements:
                paths = [
                    path
                    for path in result.traces
                    if path.asset == asset
                    and path.technique_id == requirement.technique_id
                    and path.strategy_id == requirement.strategy_id
                ]
                evidence = SigmaEvidence(
                    cve_ids=tuple(dict.fromkeys(path.cve_id for path in paths if path.cve_id)),
                    cwe_ids=tuple(dict.fromkeys(path.cwe_id for path in paths if path.cwe_id)),
                    capec_ids=tuple(
                        dict.fromkeys(path.capec_id for path in paths if path.capec_id)
                    ),
                    notes=tuple(f"trace:{path.path_id}" for path in paths),
                    source="ATT&CK detection strategy",
                    source_id=requirement.strategy_id,
                    provenance=tuple(
                        SigmaEvidenceRecord(
                            source="pipeline",
                            source_id=path.path_id,
                            rationale=(
                                "CVE → CWE → CAPEC → ATT&CK technique → "
                                "detection requirement"
                                if path.cve_id
                                else "Threat entrypoint → ATT&CK technique → detection requirement"
                            ),
                            cve_ids=(path.cve_id,) if path.cve_id else (),
                            cwe_ids=(path.cwe_id,) if path.cwe_id else (),
                            capec_ids=(path.capec_id,) if path.capec_id else (),
                        )
                        for path in paths
                    ),
                )
                try:
                    logsource = _resolve_logsource(logsource_resolver, requirement, asset)
                    if logsource is None:
                        asset_model = next(item for item in system.assets if item.name == asset)
                        logsource = asset_model.logsource or logsource_for_detection_requirement(
                            requirement
                        )
                    kwargs: dict[str, Any] = {"evidence": evidence}
                    if logsource is not None:
                        kwargs["logsource_override"] = logsource
                    kwargs["rule_id"] = _sigma_rule_id(
                        scenario_id, asset, requirement, logsource
                    )
                    kwargs["rule_kind"] = "detection_candidate"
                    rule = sigma_generator(requirement, **kwargs)
                except Exception as error:  # a failed requirement must not stop sibling rules
                    pipeline_error = PipelineError(
                        "sigma",
                        str(error),
                        asset=asset,
                        requirement_id=requirement.strategy_id,
                    )
                    errors.append(pipeline_error)
                    sigma_artifacts[asset] = (
                        *sigma_artifacts[asset],
                        SigmaArtifact(
                            asset=asset,
                            technique_id=requirement.technique_id,
                            requirement_id=requirement.strategy_id,
                            status="generation_failed",
                        ),
                    )
                    LOGGER.warning(
                        "Sigma generation failed for %s/%s: %s",
                        asset,
                        requirement.strategy_id,
                        error,
                    )
                    continue
                generated.append(rule)
                artifact = SigmaArtifact(
                    asset=asset,
                    technique_id=requirement.technique_id,
                    requirement_id=requirement.strategy_id,
                    status="generated",
                    title=rule.title,
                )
                if output_dir is not None:
                    try:
                        destination = _write_sigma(output_dir, asset, rule)
                        artifact = SigmaArtifact(
                            asset=asset,
                            technique_id=requirement.technique_id,
                            requirement_id=requirement.strategy_id,
                            status="written",
                            file=str(destination.relative_to(output_dir)),
                            title=rule.title,
                        )
                    except Exception as error:  # one output failure must not block sibling rules
                        LOGGER.warning(
                            "Sigma output failed for %s/%s: %s",
                            asset,
                            requirement.strategy_id,
                            error,
                        )
                        errors.append(
                            PipelineError(
                                "sigma-output",
                                str(error),
                                asset=asset,
                                requirement_id=requirement.strategy_id,
                            )
                        )
                        artifact = SigmaArtifact(
                            asset=asset,
                            technique_id=requirement.technique_id,
                            requirement_id=requirement.strategy_id,
                            status="write_failed",
                            title=rule.title,
                        )
                sigma_artifacts[asset] = (*sigma_artifacts[asset], artifact)
            sigma_rules[asset] = tuple(generated)
    return PipelineResult(
        result.relevant_vulnerabilities,
        result.detection_requirements,
        result.traces,
        sigma_rules,
        tuple(errors),
        result.mapping_gaps,
        result.intermediates,
        sigma_artifacts,
        scenario_id,
    )


def _fetch_vulnerabilities(
    system: SystemModel,
    *,
    nvd_client: NvdClient | None,
    vulnerability_provider: (
        Callable[[SystemModel], Mapping[str, tuple[Vulnerability, ...]]] | None
    ),
    errors: list[PipelineError],
) -> dict[str, tuple[Vulnerability, ...]]:
    if vulnerability_provider is not None:
        try:
            values = vulnerability_provider(system)
            return {asset.name: tuple(values.get(asset.name, ())) for asset in system.assets}
        except Exception as error:  # providers are external boundaries
            errors.append(PipelineError("nvd", str(error)))
            return {asset.name: () for asset in system.assets}
    if nvd_client is None:
        errors.append(PipelineError("nvd", "No vulnerability provider configured"))
        return {asset.name: () for asset in system.assets}
    result: dict[str, tuple[Vulnerability, ...]] = {}
    for asset in system.assets:
        values: dict[str, Vulnerability] = {}
        for software in asset.software:
            try:
                fetched = nvd_client.search_for_software(software)
            except Exception as error:  # network errors are isolated to one software item
                errors.append(PipelineError("nvd", str(error), asset=asset.name))
                LOGGER.warning("NVD lookup failed for %s/%s: %s", asset.name, software.name, error)
                continue
            values.update({item.cve_id: item for item in fetched})
        result[asset.name] = tuple(values.values())
    return result


def _write_sigma(output_dir: str | Path, asset: str, rule: SigmaRule) -> Path:
    directory = Path(output_dir) / "sigma"
    directory.mkdir(parents=True, exist_ok=True)
    filename = _sigma_filename(asset, rule)
    destination = directory / f"{filename}.yml"
    destination.write_text(render_sigma_yaml(rule), encoding="utf-8")
    return destination


def _resolve_logsource(
    resolver: Callable[..., Mapping[str, str]] | Mapping[str, Mapping[str, str]] | None,
    requirement: DetectionRequirement,
    asset: str,
) -> Mapping[str, str] | None:
    if resolver is None:
        return None
    if callable(resolver):
        try:
            signature = inspect.signature(resolver)
        except (TypeError, ValueError):
            # If a callable has no inspectable signature, use the documented
            # two-argument contract and let any internal TypeError propagate.
            return resolver(requirement, asset)
        try:
            signature.bind(requirement, asset)
        except TypeError:
            signature.bind(requirement)
            return resolver(requirement)
        return resolver(requirement, asset)
    if any(key in resolver for key in ("category", "product", "service")):
        return resolver  # type: ignore[return-value]
    keys = (
        f"{asset}:{requirement.strategy_id}",
        requirement.strategy_id,
        requirement.technique_id,
        asset,
        "default",
    )
    for key in keys:
        if key in resolver:
            return resolver[key]
    return None


def _append_unique(values: tuple[str, ...], value: str) -> tuple[str, ...]:
    return values if value in values else (*values, value)


def _unique_gaps(values: list[MappingGap]) -> tuple[MappingGap, ...]:
    return tuple(dict.fromkeys(values))


def _filter_asset_vulnerabilities(
    system: SystemModel,
    values: Mapping[str, tuple[Vulnerability, ...]],
) -> dict[str, tuple[Vulnerability, ...]]:
    result: dict[str, tuple[Vulnerability, ...]] = {}
    for asset in system.assets:
        candidates = values.get(asset.name, ())
        result[asset.name] = tuple(
            vulnerability
            for vulnerability in candidates
            if any(
                software.name == vulnerability.product
                and software.version in vulnerability.affected_versions
                for software in asset.software
            )
        )
    return result


def _artifact_for_rule(
    result: PipelineResult, asset: str, rule: SigmaRule
) -> SigmaArtifact | None:
    requirement_id = rule.evidence.source_id
    for artifact in result.sigma_artifacts.get(asset, ()):
        if (
            artifact.technique_id == _technique_from_rule(rule)
            and artifact.requirement_id == requirement_id
        ):
            return artifact
    return None


def _safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "item"


def _sigma_filename(asset: str, rule: SigmaRule) -> str:
    identity = "\x00".join(
        (asset, _technique_from_rule(rule), rule.evidence.source_id or rule.title)
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:10]
    return "__".join(
        _safe_filename(value)
        for value in (asset, _technique_from_rule(rule), rule.evidence.source_id or rule.title)
    ) + f"__{digest}"


def _scenario_id(system: SystemModel) -> str:
    value = system.metadata.get("name") if isinstance(system.metadata, dict) else None
    return value.strip() if isinstance(value, str) and value.strip() else "scenario"


def _sigma_rule_id(
    scenario_id: str,
    asset: str,
    requirement: DetectionRequirement,
    logsource: Mapping[str, str] | None,
) -> str:
    """Create a stable UUID-shaped identifier from rule inputs."""
    identity = "\x00".join(
        (
            scenario_id,
            asset,
            requirement.technique_id,
            requirement.strategy_id,
            repr(sorted((logsource or {}).items())),
        )
    )
    return str(uuid.uuid5(uuid.NAMESPACE_URL, identity))


def _technique_from_rule(rule: SigmaRule) -> str:
    for tag in rule.tags:
        if tag.lower().startswith("attack."):
            return tag.split(".", 1)[1].upper()
    return "technique"


def _vulnerability_mapping(item: Vulnerability) -> dict[str, Any]:
    return item.model_dump(mode="json")


def _system_mapping(system: SystemModel) -> dict[str, Any]:
    """Include generated CPE names as a first-class intermediate result."""
    result = system.model_dump(mode="json")
    for asset_model, asset_mapping in zip(system.assets, result.get("assets", [])):
        for software_model, software_mapping in zip(
            asset_model.software, asset_mapping.get("software", [])
        ):
            software_mapping["cpe_name"] = software_model.cpe_name
    return result


def _requirement_mapping(item: DetectionRequirement) -> dict[str, Any]:
    return {
        "technique_id": item.technique_id,
        "strategy_id": item.strategy_id,
        "strategy_name": item.strategy_name,
        "analytics": [
            {
                "analytic_id": analytic.analytic_id,
                "name": analytic.name,
                "description": analytic.description,
                "events": list(analytic.events),
                "fields": list(analytic.fields),
                "data_components": [
                    {
                        "component_id": component.component_id,
                        "name": component.name,
                        "data_source_id": component.data_source_id,
                        "data_source_name": component.data_source_name,
                        "log_sources": list(component.log_sources),
                    }
                    for component in analytic.data_components
                ],
            }
            for analytic in item.analytics
        ],
    }


def _threat_analysis_mapping(result: PipelineResult, system: SystemModel) -> list[dict[str, Any]]:
    """Build the common, domain-neutral analysis records.

    Each asset/requirement pair records the complete context needed for a
    report: the threat entrypoint, attacker action and ATT&CK relation, the
    telemetry requested by ATT&CK, and the telemetry actually declared by the
    scenario.  No relation is inferred when an upstream mapping is absent.
    """
    context = system.scenario
    entrypoint = context.entrypoint.model_dump(mode="json") if context.entrypoint else None
    records: list[dict[str, Any]] = []
    for asset_model in system.assets:
        asset = asset_model.name
        requirements = result.detection_requirements.get(asset, ())
        for requirement in requirements:
            required = tuple(
                dict.fromkeys((*context.required_telemetry, *requirement.required_logs))
            )
            available = tuple(asset_model.logs)
            coverage = _telemetry_coverage(required, available)
            records.append(
                {
                    "asset": asset,
                    "scenario_type": context.scenario_type,
                    "entrypoint_type": context.entrypoint_type,
                    "entrypoint": entrypoint,
                    "weakness_ids": list(context.weakness_ids),
                    "attack_pattern_ids": list(context.attack_pattern_ids),
                    "attacker_actions": list(context.attacker_actions),
                    "technique_ids": [requirement.technique_id],
                    "detection_strategy_ids": [requirement.strategy_id],
                    "analytic_ids": [item.analytic_id for item in requirement.analytics],
                    "required_telemetry": list(required),
                    "available_telemetry": list(available),
                    "coverage": coverage,
                    **_security_analysis_mapping(system, asset_model),
                    "required_privilege": context.required_privilege,
                    "privilege_transition": context.privilege_transition,
                    "required_authentication_logs": list(context.required_authentication_logs),
                    "evidence": list(context.evidence),
                    "rationale": context.rationale,
                    "confidence": context.confidence,
                    "mapping_gaps": [
                        gap.to_mapping()
                        for gap in result.mapping_gaps
                        if gap.asset == asset
                    ],
                }
            )
    # A direct technique with no detection strategy is still an analysis
    # record.  Keeping it visible is important for counterexamples.  The same
    # fallback also keeps CVE scenarios with an unresolved mapping visible.
    if not records:
        for asset_model in system.assets:
            asset_gaps = [
                gap.to_mapping() for gap in result.mapping_gaps if gap.asset == asset_model.name
            ]
            required = tuple(context.required_telemetry)
            inferred_techniques = tuple(
                result.intermediates.get(asset_model.name, {}).get("technique_ids", ())
            )
            records.append(
                {
                    "asset": asset_model.name,
                    "scenario_type": context.scenario_type,
                    "entrypoint_type": context.entrypoint_type,
                    "entrypoint": entrypoint,
                    "weakness_ids": list(context.weakness_ids),
                    "attack_pattern_ids": list(context.attack_pattern_ids),
                    "attacker_actions": list(context.attacker_actions),
                    "technique_ids": list(context.technique_ids or inferred_techniques),
                    "detection_strategy_ids": [],
                    "analytic_ids": [],
                    "required_telemetry": list(required),
                    "available_telemetry": list(asset_model.logs),
                    "coverage": _telemetry_coverage(required, tuple(asset_model.logs)),
                    **_security_analysis_mapping(system, asset_model),
                    "required_privilege": context.required_privilege,
                    "privilege_transition": context.privilege_transition,
                    "required_authentication_logs": list(context.required_authentication_logs),
                    "evidence": list(context.evidence),
                    "rationale": context.rationale,
                    "confidence": context.confidence,
                    "mapping_gaps": asset_gaps,
                }
            )
    return records


def _telemetry_coverage(required: tuple[str, ...], available: tuple[str, ...]) -> dict[str, Any]:
    """Compare human ATT&CK names and scenario log slugs consistently."""
    available_keys = {_telemetry_key(value) for value in available}
    covered = tuple(value for value in required if _telemetry_key(value) in available_keys)
    missing = tuple(value for value in required if _telemetry_key(value) not in available_keys)
    ratio = len(covered) / len(required) if required else 1.0
    return {
        "required": list(required),
        "available": list(available),
        "covered": list(covered),
        "missing": list(missing),
        "coverage_ratio": ratio,
        "status": "complete" if not missing else ("unavailable" if not covered else "partial"),
    }


def _security_analysis_mapping(system: SystemModel, asset: Any) -> dict[str, Any]:
    """Expose declared trust and access prerequisites without guessing.

    A flow is associated with an asset only when that asset is one of its
    endpoints.  External endpoints such as ``internet`` remain valid and are
    retained in the output.  Missing values are represented as ``None`` or an
    empty collection, never inferred from the protocol or zone names.
    """
    flows = (
        flow
        for flow in system.flows
        if flow.source == asset.name or flow.destination == asset.name
    )
    flow_security: list[dict[str, Any]] = []
    for flow in flows:
        flow_security.append(
            {
                "from": flow.source,
                "to": flow.destination,
                "protocol": flow.protocol,
                "trust_boundary": flow.trust_boundary,
                "authentication": (
                    flow.authentication.model_dump(mode="json")
                    if flow.authentication is not None
                    else None
                ),
                "authorization": (
                    flow.authorization.model_dump(mode="json")
                    if flow.authorization is not None
                    else None
                ),
            }
        )
    return {
        "trust_zone": asset.trust_zone,
        "privilege_level": asset.privilege_level,
        "trust_boundaries": list(
            dict.fromkeys(
                item["trust_boundary"] for item in flow_security if item["trust_boundary"]
            )
        ),
        "authentication_conditions": [
            item["authentication"] for item in flow_security if item["authentication"] is not None
        ],
        "authorization_conditions": [
            item["authorization"] for item in flow_security if item["authorization"] is not None
        ],
        "flow_security": flow_security,
    }


def _telemetry_key(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")
    aliases = {
        "process_creation": "process_creation",
        "process_execution": "process_creation",
        "file_access": "file_event",
        "file_activity": "file_event",
        "network_connection_creation": "network_connection",
        "network_connection": "network_connection",
        "dns_query": "dns",
    }
    return aliases.get(normalized, normalized)
