from parsers.zeek_parser import load_zeek_notices

from correlation_engine import (
    correlate_events,
    print_incident
)

from database import (
    init_database,
    save_incident
)


ZEEK_LOG = "sample-logs/zeek_notice.jsonl"


def main():
    print("\nHomeSOC Zeek Ingestion")
    print("-" * 45)

    # Make sure the database and tables exist
    init_database()

    # Load and normalize Zeek events
    events = load_zeek_notices(
        ZEEK_LOG
    )

    print(
        f"Parsed {len(events)} relevant "
        f"Zeek events."
    )

    # Correlate related events into incidents
    incidents = correlate_events(
        events,
        window_minutes=10
    )

    print(
        f"Generated {len(incidents)} "
        f"incident(s)."
    )

    # Display and store each incident
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