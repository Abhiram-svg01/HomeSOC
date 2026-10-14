from parsers.suricata_parser import load_suricata_eve
from parsers.zeek_parser import load_zeek_notices
from parsers.wazuh_parser import load_wazuh_alerts

from correlation_engine import (
    correlate_events,
    print_incident
)

from database import (
    init_database,
    save_incident
)


SURICATA_LOG = "sample-logs/suricata_eve.jsonl"
ZEEK_LOG = "sample-logs/zeek_notice.jsonl"
WAZUH_LOG = "sample-logs/wazuh_alerts.jsonl"


def main():
    print("\nHomeSOC Unified Security Ingestion")
    print("-" * 50)

    init_database()

    suricata_events = load_suricata_eve(
        SURICATA_LOG
    )

    zeek_events = load_zeek_notices(
        ZEEK_LOG
    )

    wazuh_events = load_wazuh_alerts(
        WAZUH_LOG
    )

    print(
        f"Suricata events : {len(suricata_events)}"
    )

    print(
        f"Zeek events     : {len(zeek_events)}"
    )

    print(
        f"Wazuh events    : {len(wazuh_events)}"
    )

    all_events = (
        suricata_events
        + zeek_events
        + wazuh_events
    )

    print(
        f"\nTotal normalized events: "
        f"{len(all_events)}"
    )

    incidents = correlate_events(
        all_events,
        window_minutes=10
    )

    print(
        f"Generated {len(incidents)} "
        f"correlated incident(s)."
    )

    for number, incident in enumerate(
        incidents,
        start=1
    ):
        print_incident(
            incident,
            incident_number=number
        )

        incident_id = save_incident(
            incident
        )

        print(
            f"Stored as HomeSOC "
            f"incident #{incident_id:04d}"
        )


if __name__ == "__main__":
    main()