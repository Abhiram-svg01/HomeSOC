from parsers.suricata_parser import load_suricata_eve

from correlation_engine import (
    correlate_events,
    print_incident
)

from database import (
    init_database,
    save_incident
)


SURICATA_LOG = (
    "sample-logs/suricata_eve.jsonl"
)


def main():
    print("\nHomeSOC Suricata Ingestion")
    print("-" * 45)

    init_database()

    events = load_suricata_eve(
        SURICATA_LOG
    )

    print(
        f"Parsed {len(events)} relevant "
        f"Suricata events."
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