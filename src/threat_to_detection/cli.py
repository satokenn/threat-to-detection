"""Command-line entry point for inspecting a system model."""

import argparse
import sys

from threat_to_detection.collectors.nvd import NvdApiError, NvdClient
from threat_to_detection.models.system import load_system


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


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "fetch-cves":
        return fetch_cves(argv[1:])
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
