import json
from pathlib import Path

from risk_engine import create_security_event
from correlation_engine import correlate_events, print_incident
from database import init_database, save_incident

def load_json_events(file_path):
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def normalize_events(raw_events):
    normalized_events = []

    for raw_event in raw_events:
        event = create_security_event(
            source=raw_event["source"],
            event_type=raw_event["event_type"],
            src_ip=raw_event["src_ip"],
            dst_ip=raw_event["dst_ip"],
            asset_ip=raw_event.get("asset_ip"),
            description=raw_event["description"],
            timestamp=raw_event.get("timestamp")
        )

        normalized_events.append(event)

    return normalized_events


def main():
    log_file = "sample-logs/security_events.json"

    init_database()

    print("\nHomeSOC Log Ingestion")
    print("-" * 40)

    raw_events = load_json_events(log_file)
    print(f"Loaded {len(raw_events)} raw events.")

    events = normalize_events(raw_events)
    print(f"Normalized {len(events)} events.")

    incidents = correlate_events(events)
    print(f"Generated {len(incidents)} incident(s).")

    for number, incident in enumerate(incidents, start=1):
        print_incident(
            incident,
            incident_number=number
        )

        incident_id = save_incident(incident)

        print(
            f"Incident saved to database with ID {incident_id}."
        )


if __name__ == "__main__":
    main()