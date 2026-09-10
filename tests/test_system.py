import json
from pathlib import Path

import pytest

from threat_to_detection.models.system import build_cpe, load_system


def test_load_system_example() -> None:
    system = load_system(Path("examples/web-system.yaml"))

    assert [asset.name for asset in system.assets] == ["web-server", "database"]
    assert system.assets[0].software[0].version == "1.0"
    assert system.assets[0].software[0].cpe_name == (
        "cpe:2.3:a:example-vendor:example-product:1.0:*:*:*:*:*:*:*"
    )
    assert system.assets[0].exposed_to == ("internet",)
    assert system.flows[0].destination == "web-server"


def test_asset_logsource_is_preserved() -> None:
    system = load_system("evaluations/scenario.yaml")

    assert system.assets[0].logsource == {"category": "process_creation"}


def test_invalid_asset_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text("system:\n  assets:\n    - type: server\n", encoding="utf-8")

    try:
        load_system(path)
    except ValueError as error:
        assert "name" in str(error)
    else:
        raise AssertionError("invalid asset should be rejected")


def test_build_cpe_from_vendor_product_version() -> None:
    assert build_cpe("Apache", "HTTP Server", "2.4.58") == (
        "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"
    )


def test_security_boundary_and_access_conditions_are_loaded(tmp_path: Path) -> None:
    path = tmp_path / "security-boundary.yaml"
    path.write_text(
        """system:
  assets:
    - name: web-server
      trust_zone: dmz
      privilege_level: service
    - name: database
      trust_zone: internal
  flows:
    - from: web-server
      to: database
      trust_boundary: dmz-to-internal
      authentication:
        required: true
        method: service_account
        principal: web-service
        identity_source: workload-identity
      authorization:
        required: true
        roles: [read_only]
        scopes: [database.read]
        privilege: read
""",
        encoding="utf-8",
    )

    system = load_system(path)
    assert system.assets[0].trust_zone == "dmz"
    assert system.assets[0].privilege_level == "service"
    flow = system.flows[0]
    assert flow.trust_boundary == "dmz-to-internal"
    assert flow.authentication is not None
    assert flow.authentication.required is True
    assert flow.authentication.principal == "web-service"
    assert flow.authorization is not None
    assert flow.authorization.roles == ("read_only",)
    assert flow.authorization.privilege == "read"


@pytest.mark.parametrize(
    "document",
    [
        "system:\n  assets:\n    - name: web\n      trust_zone: ' '\n",
        (
            "system:\n  assets:\n    - name: web\n  flows:\n    - from: web\n"
            "      to: db\n      trust_boundary: ' '\n"
        ),
        (
            "system:\n  assets:\n    - name: web\n  flows:\n    - from: web\n"
            "      to: db\n      authentication:\n        required: 'yes'\n"
        ),
        (
            "system:\n  assets:\n    - name: web\n  flows:\n    - from: web\n"
            "      to: db\n      authorization:\n        roles: ['']\n"
        ),
    ],
)
def test_security_conditions_reject_invalid_values(tmp_path: Path, document: str) -> None:
    path = tmp_path / "invalid-security.yaml"
    path.write_text(document, encoding="utf-8")
    with pytest.raises(ValueError):
        load_system(path)


def test_dfd_declares_security_context_metadata() -> None:
    document = json.loads(
        Path("docs/threat-to-detection.dataflow.json").read_text(encoding="utf-8")
    )
    security_model = document["meta"]["security_model"]
    assert security_model["asset_fields"] == ["trust_zone", "privilege_level"]
    assert security_model["flow_fields"] == [
        "trust_boundary",
        "authentication",
        "authorization",
    ]
    assert security_model["unknown_policy"]
