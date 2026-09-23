from risk_engine import create_security_event


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


def correlate_events(events):
    incidents = {}

    for event in events:
        asset = event["asset_ip"]

        if asset not in incidents:
            incidents[asset] = {
                "asset_ip": asset,
                "events": [],
                "total_score": 0,
                "stages": []
            }

        incidents[asset]["events"].append(event)
        incidents[asset]["total_score"] += event["risk_score"]

        stage = ATTACK_STAGES.get(
            event["event_type"],
            "Unknown"
        )

        if stage not in incidents[asset]["stages"]:
            incidents[asset]["stages"].append(stage)

    return incidents


def calculate_incident_severity(score):

    if score >= 120:
        return "CRITICAL"

    elif score >= 75:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    return "LOW"


def print_incident(incident):

    severity = calculate_incident_severity(
        incident["total_score"]
    )

    print("\n" + "=" * 55)
    print("HOMESOC INCIDENT DETECTED")
    print("=" * 55)

    print(f"Protected Asset : {incident['asset_ip']}")
    print(f"Events          : {len(incident['events'])}")
    print(f"Incident Score  : {incident['total_score']}")
    print(f"Severity        : {severity}")

    print("\nAttack Progression:")

    print(" -> ".join(incident["stages"]))

    print("\nEvidence:")

    for event in incident["events"]:
        print(
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


if __name__ == "__main__":

    HOME_PC = "192.168.1.10"

    events = [

        create_security_event(
            source="Suricata",
            event_type="Network Scan",
            src_ip="192.168.1.50",
            dst_ip=HOME_PC,
            asset_ip=HOME_PC,
            description="Reconnaissance activity detected"
        ),

        create_security_event(
            source="Wazuh",
            event_type="Multiple Failed Logins",
            src_ip="192.168.1.50",
            dst_ip=HOME_PC,
            asset_ip=HOME_PC,
            description="Repeated login attempts detected"
        ),

        create_security_event(
            source="Zeek",
            event_type="Suspicious DNS",
            src_ip=HOME_PC,
            dst_ip="8.8.8.8",
            asset_ip=HOME_PC,
            description="Suspicious DNS communication"
        ),

        create_security_event(
            source="Suricata",
            event_type="Command and Control",
            src_ip=HOME_PC,
            dst_ip="45.33.32.156",
            asset_ip=HOME_PC,
            description="Possible C2 communication"
        )
    ]

    incidents = correlate_events(events)

    for incident in incidents.values():
        print_incident(incident)