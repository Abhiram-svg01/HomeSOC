import json
from datetime import datetime
from pathlib import Path

from risk_engine import create_security_event


def convert_zeek_timestamp(timestamp):
    """
    Convert Zeek timestamps into the ISO format used by HomeSOC.
    """

    if timestamp is None:
        return datetime.now().isoformat(timespec="seconds")

    if isinstance(timestamp, (int, float)):
        return datetime.fromtimestamp(
            timestamp
        ).isoformat(timespec="seconds")

    return str(timestamp)


def classify_zeek_notice(record):
    """
    Convert Zeek notice types into HomeSOC event types.
    """

    note = record.get(
        "note",
        ""
    ).lower()

    message = record.get(
        "msg",
        ""
    ).lower()

    if (
        "scan" in note
        or "port_scan" in note
        or "scanned" in message
    ):
        return "Network Scan"

    if (
        "password_guessing" in note
        or "authentication attempts" in message
        or "brute" in message
    ):
        return "Multiple Failed Logins"

    if (
        "intel" in note
        or "command and control" in message
        or "c2" in message
        or "threat intelligence" in message
    ):
        return "Command and Control"

    return None


def determine_asset_ip(
    record,
    homesoc_event_type
):
    """
    Decide which host HomeSOC should treat as the protected asset.
    """

    src_ip = record.get(
        "src",
        record.get(
            "id.orig_h",
            "unknown"
        )
    )

    dst_ip = record.get(
        "dst",
        record.get(
            "id.resp_h",
            "unknown"
        )
    )

    if homesoc_event_type in (
        "Network Scan",
        "Multiple Failed Logins"
    ):
        return dst_ip

    if homesoc_event_type == "Command and Control":
        return src_ip

    return dst_ip


def build_description(record):
    message = record.get(
        "msg",
        "Zeek security notice detected"
    )

    return f"Zeek notice: {message}"


def parse_record(record):
    homesoc_event_type = classify_zeek_notice(
        record
    )

    if homesoc_event_type is None:
        return None

    src_ip = record.get(
        "src",
        record.get(
            "id.orig_h",
            "unknown"
        )
    )

    dst_ip = record.get(
        "dst",
        record.get(
            "id.resp_h",
            "unknown"
        )
    )

    asset_ip = determine_asset_ip(
        record,
        homesoc_event_type
    )

    timestamp = convert_zeek_timestamp(
        record.get("ts")
    )

    return create_security_event(
        source="Zeek",
        event_type=homesoc_event_type,
        src_ip=src_ip,
        dst_ip=dst_ip,
        asset_ip=asset_ip,
        description=build_description(
            record
        ),
        timestamp=timestamp
    )


def load_zeek_notices(file_path):
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Zeek log not found: {file_path}"
        )

    events = []

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:

        for line_number, line in enumerate(
            file,
            start=1
        ):
            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)

            except json.JSONDecodeError:
                print(
                    f"Skipping invalid Zeek JSON "
                    f"on line {line_number}"
                )
                continue

            event = parse_record(
                record
            )

            if event:
                events.append(
                    event
                )

    return events