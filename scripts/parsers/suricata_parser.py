import json
from pathlib import Path

from risk_engine import create_security_event


def classify_suricata_event(record):
    """
    Convert Suricata EVE records into HomeSOC event types.
    """

    suricata_type = record.get("event_type", "")

    if suricata_type == "alert":
        alert = record.get("alert", {})

        signature = alert.get(
            "signature",
            ""
        ).lower()

        category = alert.get(
            "category",
            ""
        ).lower()

        if "scan" in signature or "scan" in category:
            return "Network Scan"

        if (
            "command and control" in signature
            or "trojan" in category
        ):
            return "Command and Control"

        if "malware" in signature:
            return "Malware Alert"

    if suricata_type == "dns":
        dns = record.get("dns", {})

        domain = dns.get(
            "rrname",
            ""
        ).lower()

        suspicious_terms = (
            ".invalid",
            "suspicious",
            "malware",
            "command"
        )

        if any(
            term in domain
            for term in suspicious_terms
        ):
            return "Suspicious DNS"

    return None


def determine_asset_ip(
    record,
    homesoc_event_type
):
    """
    Determine which device should be treated
    as the protected residential asset.
    """

    src_ip = record.get(
        "src_ip",
        "unknown"
    )

    dst_ip = record.get(
        "dest_ip",
        "unknown"
    )

    # Scans generally target the protected machine
    if homesoc_event_type == "Network Scan":
        return dst_ip

    # DNS/C2/malware traffic generally originates
    # from the potentially affected home device
    if homesoc_event_type in (
        "Suspicious DNS",
        "Command and Control",
        "Malware Alert"
    ):
        return src_ip

    return dst_ip


def build_description(
    record,
    homesoc_event_type
):
    if record.get("event_type") == "alert":

        alert = record.get(
            "alert",
            {}
        )

        signature = alert.get(
            "signature",
            "Unknown Suricata alert"
        )

        return (
            f"Suricata alert: {signature}"
        )

    if homesoc_event_type == "Suspicious DNS":

        dns = record.get(
            "dns",
            {}
        )

        domain = dns.get(
            "rrname",
            "unknown"
        )

        return (
            f"Suspicious DNS query observed: "
            f"{domain}"
        )

    return "Suricata security event detected"


def parse_record(record):
    homesoc_event_type = (
        classify_suricata_event(record)
    )

    if homesoc_event_type is None:
        return None

    src_ip = record.get(
        "src_ip",
        "unknown"
    )

    dst_ip = record.get(
        "dest_ip",
        "unknown"
    )

    asset_ip = determine_asset_ip(
        record,
        homesoc_event_type
    )

    return create_security_event(
        source="Suricata",
        event_type=homesoc_event_type,
        src_ip=src_ip,
        dst_ip=dst_ip,
        asset_ip=asset_ip,
        description=build_description(
            record,
            homesoc_event_type
        ),
        timestamp=record.get(
            "timestamp"
        )
    )


def load_suricata_eve(file_path):
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Suricata log not found: {file_path}"
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
                    f"Skipping invalid JSON "
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