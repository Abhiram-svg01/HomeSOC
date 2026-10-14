from parsers.wazuh_parser import load_wazuh_alerts

from correlation_engine import (
    correlate_events,
    print_incident
)

from database import (
    init_database,
    save_incident
)


WAZUH_LOG = "sample-logs/wazuh_alerts.jsonl"


def main():
    print("\nHomeSOC Wazuh Ingestion")
    print("-" * 45)

    init_database()

    events = load_wazuh_alerts(
        WAZUH_LOG
    )

    print(
        f"Parsed {len(events)} relevant "
        f"Wazuh events."
    )

    incidents = correlate_events(
        events,
        window_minutes=10
    )

    print(
        f"Generated {len(incidents)} "
        f"incident(s)."
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