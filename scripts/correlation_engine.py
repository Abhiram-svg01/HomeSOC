from datetime import datetime, timedelta


ATTACK_STAGES = {
    "Network Scan": "Reconnaissance",
    "Failed Login": "Credential Access",
    "Multiple Failed Logins": "Credential Access",
    "Privilege Escalation": "Privilege Escalation",
    "File Integrity Change": "System Modification",
    "Suspicious DNS": "Command and Control",
    "Command and Control": "Command and Control",
    "Malware Alert": "Execution"
}


def parse_timestamp(timestamp):
    return datetime.fromisoformat(timestamp)


def correlate_events(events, window_minutes=10):
    correlation_window = timedelta(minutes=window_minutes)

    events = sorted(
        events,
        key=lambda event: parse_timestamp(event["timestamp"])
    )

    incidents = []

    for event in events:
        event_time = parse_timestamp(event["timestamp"])
        asset = event["asset_ip"]

        matching_incident = None

        for incident in reversed(incidents):

            if incident["asset_ip"] != asset:
                continue

            last_time = parse_timestamp(
                incident["events"][-1]["timestamp"]
            )

            if event_time - last_time <= correlation_window:
                matching_incident = incident

            break

        if matching_incident is None:

            matching_incident = {
                "asset_ip": asset,
                "events": [],
                "total_score": 0,
                "stages": [],
                "start_time": event["timestamp"],
                "end_time": event["timestamp"]
            }

            incidents.append(matching_incident)

        matching_incident["events"].append(event)
        matching_incident["total_score"] += event["risk_score"]
        matching_incident["end_time"] = event["timestamp"]

        stage = ATTACK_STAGES.get(
            event["event_type"],
            "Unknown"
        )

        if stage not in matching_incident["stages"]:
            matching_incident["stages"].append(stage)

    return incidents


def calculate_incident_severity(score):

    if score >= 120:
        return "CRITICAL"

    if score >= 75:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


def print_incident(incident, incident_number=None):

    severity = calculate_incident_severity(
        incident["total_score"]
    )

    print("\n" + "=" * 55)

    if incident_number:
        print(f"HOMESOC INCIDENT #{incident_number:04d}")
    else:
        print("HOMESOC INCIDENT")

    print("=" * 55)

    print(f"Protected Asset : {incident['asset_ip']}")
    print(f"Start Time      : {incident['start_time']}")
    print(f"End Time        : {incident['end_time']}")
    print(f"Events          : {len(incident['events'])}")
    print(f"Incident Score  : {incident['total_score']}")
    print(f"Severity        : {severity}")

    print("\nAttack Progression:")

    print(" -> ".join(incident["stages"]))

    print("\nEvidence:")

    for event in incident["events"]:

        print(
            f"{event['timestamp']} | "
            f"[{event['source']}] "
            f"{event['event_type']} "
            f"({event['risk_score']} points)"
        )

    if len(incident["stages"]) >= 3:
        print(
            "\nAssessment: Possible multi-stage "
            "attack detected."
        )

    print("=" * 55)