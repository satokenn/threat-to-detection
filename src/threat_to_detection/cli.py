"""Command-line entry point for system inspection and end-to-end analysis."""

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path
from typing import Any

from threat_to_detection.collectors.attack import AttackCollector, AttackDataError
from threat_to_detection.collectors.capec import CapecCollector, CapecDataError
from threat_to_detection.collectors.nvd import NvdApiError, NvdClient
from threat_to_detection.models.system import load_system
from threat_to_detection.services.pipeline import run_analysis


LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect a threat model YAML file")
    parser.add_argument("system", help="Path to the system model YAML")
    return parser


def build_fetch_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fetch CVEs from the NVD API 2.0")
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--cve-id")
    selector.add_argument("--cpe-name")
    selector.add_argument("--keyword")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--no-cache", action="store_true")
    return parser


def build_analyze_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threat-to-detection analyze",
        description="Run the CVE-to-Sigma analysis pipeline for a system YAML",
    )
    parser.add_argument("scenario", help="Path to the system model YAML")
    parser.add_argument(
        "--output-dir",
        "--output",
        default="output",
        help="Artifact root for analysis.json and sigma/ (default: output)",
    )
    parser.add_argument(
        "--nvd-cache",
        "--cache-dir",
        dest="nvd_cache",
        default="data/cache/nvd",
        help="NVD response cache directory; use an empty value to disable cache",
    )
    parser.add_argument(
        "--nvd-fixture",
        "--vulnerability-fixture",
        dest="nvd_fixture",
        help="Offline NVD JSON response fixture",
    )
    parser.add_argument(
        "--capec-path",
        "--capec-fixture",
        "--capec-xml",
        "--capec",
        dest="capec_path",
        help="CAPEC XML path (also used as an offline fixture)",
    )
    parser.add_argument(
        "--attack-path",
        "--attack-fixture",
        "--attack-json",
        "--attack",
        dest="attack_path",
        help="Enterprise ATT&CK STIX JSON path (also used as an offline fixture)",
    )
    network = parser.add_mutually_exclusive_group()
    network.add_argument(
        "--offline",
        action="store_true",
        help="Disable all network access; provide --nvd-fixture for offline CVE data",
    )
    network.add_argument(
        "--online",
        action="store_true",
        help="Allow downloads for missing CAPEC/ATT&CK datasets",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return exit code 3 when the analysis is partial",
    )
    parser.add_argument("--logsource-category")
    parser.add_argument("--logsource-product")
    parser.add_argument("--logsource-service")
    parser.add_argument("--verbose", action="store_true", help="Enable diagnostic logging")
    return parser


def fetch_cves(argv: list[str]) -> int:
    args = build_fetch_parser().parse_args(argv)
    try:
        vulnerabilities = NvdClient(
            cache_dir=None if args.no_cache else "data/cache/nvd"
        ).search_cves(
            cve_id=args.cve_id,
            cpe_name=args.cpe_name,
            keyword=args.keyword,
            results_per_page=args.limit,
        )
    except (NvdApiError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    for vulnerability in vulnerabilities:
        score = f" CVSS={vulnerability.cvss_score}" if vulnerability.cvss_score else ""
        print(f"{vulnerability.cve_id}{score} {vulnerability.description}")
    return 0


def analyze_scenario(argv: list[str]) -> int:
    args = build_analyze_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    try:
        system = load_system(args.scenario)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    output_dir = Path(args.output_dir)
    errors: list[str] = []
    nvd_client = _build_nvd_client(
        args.nvd_fixture,
        args.nvd_cache,
        errors,
        offline=args.offline,
    )
    capec_dataset = _load_capec(args.capec_path, args.offline, errors)
    attack_dataset = _load_attack(args.attack_path, args.offline, errors)
    result = run_analysis(
        system,
        nvd_client=nvd_client,
        capec_dataset=capec_dataset,
        attack_dataset=attack_dataset,
        output_dir=output_dir,
        logsource_resolver=_logsource_override(args),
    )
    all_errors = [*errors, *(error.message for error in result.errors)]
    document = result.to_mapping(system)
    if all_errors:
        # Keep loader errors visible in the machine-readable report too.
        document["errors"] = [
            *document.get("errors", []),
        ] + [
            {
                "stage": (
                    "nvd"
                    if message.startswith(("Offline mode", "Could not load NVD"))
                    else "dataset"
                ),
                "message": message,
            }
            for message in errors
        ]
        document["status"] = "partial"
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "analysis.json").write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    except OSError as error:
        print(f"error: could not write analysis.json: {error}", file=sys.stderr)
        return 2
    try:
        _write_manifest(output_dir, document, result)
    except OSError as error:
        print(f"error: could not write manifest.json: {error}", file=sys.stderr)
        return 2

    for message in all_errors:
        LOGGER.warning(message)
    print(f"analysis: {output_dir / 'analysis.json'}")
    print(f"assets: {len(system.assets)}")
    print(f"trace paths: {len(result.traces)}")
    print(f"sigma rules: {sum(len(rules) for rules in result.sigma_rules.values())}")
    return 3 if args.strict and document.get("status") != "success" else 0


def _write_manifest(output_dir: Path, document: dict[str, Any], result: Any) -> None:
    """Write a manifest for files owned by this analysis run."""
    files: list[dict[str, Any]] = []
    owned_paths = {Path("analysis.json")}
    for artifacts in result.sigma_artifacts.values():
        for artifact in artifacts:
            if artifact.file:
                owned_paths.add(Path(artifact.file))
    for relative_path in sorted(owned_paths):
        absolute_path = output_dir / relative_path
        if not absolute_path.is_file():
            continue
        files.append(
            {
                "path": relative_path.as_posix(),
                "kind": "analysis" if relative_path.name == "analysis.json" else "sigma",
                "status": "written",
                "sha256": hashlib.sha256(absolute_path.read_bytes()).hexdigest(),
            }
        )
    manifest = {
        "schema_version": "1.0",
        "scenario_id": document.get("scenario_id"),
        "status": document.get("status"),
        "files": files,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _build_nvd_client(
    fixture: str | None,
    cache_dir: str | None,
    errors: list[str],
    *,
    offline: bool = False,
) -> NvdClient | None:
    if offline and not fixture:
        errors.append("Offline mode requires --nvd-fixture; NVD network access is disabled")
        return None
    if not fixture:
        return NvdClient(cache_dir=cache_dir or None)
    try:
        payload = json.loads(Path(fixture).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("NVD fixture must contain a JSON object")
    except (OSError, json.JSONDecodeError, ValueError) as error:
        errors.append(f"Could not load NVD fixture {fixture}: {error}")
        payload = {"vulnerabilities": []}

    def opener(_request: Any, _timeout: float) -> dict[str, Any]:
        return payload

    return NvdClient(cache_dir=None, opener=opener)


def _logsource_override(args: argparse.Namespace) -> dict[str, str] | None:
    values = {
        key: value
        for key, value in (
            ("category", args.logsource_category),
            ("product", args.logsource_product),
            ("service", args.logsource_service),
        )
        if value
    }
    return values or None


def _load_capec(path: str | None, offline: bool, errors: list[str]):
    destination = Path(path) if path else Path("data/cache/capec_latest.xml")
    collector = CapecCollector()
    if not destination.exists() and not offline and not path:
        try:
            collector.download(destination)
        except CapecDataError as error:
            errors.append(str(error))
            return None
    if not destination.exists():
        errors.append(f"CAPEC dataset not found: {destination}")
        return None
    try:
        return collector.load(destination)
    except CapecDataError as error:
        errors.append(str(error))
        return None


def _load_attack(path: str | None, offline: bool, errors: list[str]):
    destination = Path(path) if path else Path("data/cache/enterprise-attack.json")
    collector = AttackCollector()
    if not destination.exists() and not offline and not path:
        try:
            collector.download(destination)
        except AttackDataError as error:
            errors.append(str(error))
            return None
    if not destination.exists():
        errors.append(f"ATT&CK dataset not found: {destination}")
        return None
    try:
        return collector.load(destination)
    except AttackDataError as error:
        errors.append(str(error))
        return None


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "fetch-cves":
        return fetch_cves(argv[1:])
    if argv and argv[0] == "analyze":
        return analyze_scenario(argv[1:])
    args = build_parser().parse_args(argv)
    try:
        system = load_system(args.system)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    print(f"assets: {len(system.assets)}")
    print(f"flows: {len(system.flows)}")
    for asset in system.assets:
        software = ", ".join(f"{item.name} {item.version}" for item in asset.software)
        print(f"- {asset.name} ({asset.type}): {software or 'no software listed'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
