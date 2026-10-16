
"""
HomeSOC Authentication Lab Adapter

Loads simulated authentication telemetry and
converts detected login bursts into normalized
HomeSOC security events.

Only derived detections are forwarded to the
correlation engine to avoid double-counting
individual failed-login attempts.
"""

import json
from pathlib import Path

from detection_rules import (
    detect_failed_login_bursts,
    parse_event_time
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent

AUTH_LOG = (
    PROJECT_ROOT
    / "sample-logs"
    / "auth_failures.jsonl"
)


def load_auth_lab_detections(file_path=AUTH_LOG):

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Authentication log not found: {path}"
        )

    records = []

    with path.open("r", encoding="utf-8") as file:

        for line_number, line in enumerate(file, 1):

            if not line.strip():
                continue

            try:
                records.append(json.loads(line))

            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Invalid JSON on line {line_number}"
                ) from error

    detections = detect_failed_login_bursts(records)

    normalized_detections = []

    for detection in detections:

        event = detection.copy()

        # Existing HomeSOC sample events use
        # timezone-naive ISO timestamps.
        # Convert the lab's UTC timestamps
        # into that same representation.

        event["timestamp"] = (
            parse_event_time(event["timestamp"])
            .replace(tzinfo=None)
            .isoformat(timespec="seconds")
        )

        event["description"] += (
            " Source: simulated AuthLab telemetry."
        )

        normalized_detections.append(event)

    return records, normalized_detections


if __name__ == "__main__":

    records, detections = load_auth_lab_detections()

    print("\nHomeSOC Authentication Ingestion Adapter")
    print("=" * 45)

    print(f"Log records loaded: {len(records)}")
    print(f"Rule detections: {len(detections)}")

    for event in detections:

        print("\nDetection:", event["rule_id"])
        print("Event:", event["event_type"])
        print("Source IP:", event["src_ip"])
        print("Protected Asset:", event["asset_ip"])
        print("Distinct Attempts:", event["attempt_count"])
        print("Risk Score:", event["risk_score"])

    print("\nADAPTER VALIDATION COMPLETE")
