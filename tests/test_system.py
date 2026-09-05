from pathlib import Path

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
