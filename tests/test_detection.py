from threat_to_detection.models.detection import DetectionGap


def test_detection_gap_reports_missing_logs_in_required_order() -> None:
    gap = DetectionGap(
        asset="web-server",
        required_logs=("process_creation", "file_activity", "network_connection"),
        available_logs=("process_creation", "network_connection"),
    )

    assert gap.missing_logs == ("file_activity",)
