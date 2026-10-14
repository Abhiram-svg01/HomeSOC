import json
from pathlib import Path

from risk_engine import create_security_event


def classify_wazuh_alert(record):
    """
    Convert Wazuh alerts into HomeSOC event types.
    """

    rule = record.get("rule", {})

    description = rule.get(
        "description",
        ""
    ).lower()

    groups = [
        str(group).lower()
        for group in rule.get("groups", [])
    ]

    combined_groups = " ".join(groups)

    if (
        "authentication failure" in description
        or "failed login" in description
        or "authentication_failed" in combined_groups
        or "brute" in description
    ):
        return "Multiple Failed Logins"

    if (
        "privilege escalation" in description
        or "privilege_escalation" in combined_groups
        or "sudo" in combined_groups
    ):
        return "Privilege Escalation"

    if (
        "file integrity" in description
        or "syscheck" in combined_groups
        or "fim" in combined_groups
    ):
        return "File Integrity Change"

    if (
        "malware" in description
        or "trojan" in description
        or "rootkit" in description
    ):
        return "Malware Alert"

    return None


def determine_asset_ip(record):
    """
    Prefer the Wazuh agent IP as the protected asset.
    """

    agent = record.get(
        "agent",
        {}
    )

    agent_ip = agent.get(
        "ip"
    )

    if agent_ip:
        return agent_ip

    data = record.get(
        "data",
        {}
    )

    return data.get(
        "dstip",
        "unknown"
    )


def build_description(record):
    rule = record.get(
        "rule",
        {}
    )

    description = rule.get(
        "description",
        "Wazuh security alert"
    )

    full_log = record.get(
        "full_log",
        ""
    )

    if full_log:
        return (
            f"Wazuh alert: {description}. "
            f"Evidence: {full_log}"
        )

    return f"Wazuh alert: {description}"


def parse_record(record):
    homesoc_event_type = classify_wazuh_alert(
        record
    )

    if homesoc_event_type is None:
        return None

    data = record.get(
        "data",
        {}
    )

    src_ip = data.get(
        "srcip",
        "unknown"
    )

    dst_ip = data.get(
        "dstip",
        determine_asset_ip(record)
    )

    return create_security_event(
        source="Wazuh",
        event_type=homesoc_event_type,
        src_ip=src_ip,
        dst_ip=dst_ip,
        asset_ip=determine_asset_ip(record),
        description=build_description(record),
        timestamp=record.get("timestamp")
    )


def load_wazuh_alerts(file_path):
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Wazuh log not found: {file_path}"
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
                    f"Skipping invalid Wazuh JSON "
                    f"on line {line_number}"
                )
                continue

            event = parse_record(record)

            if event:
                events.append(event)

    return events