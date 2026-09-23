from event_parser import normalize_event


EVENT_SCORES = {
    "Network Scan": 25,
    "Failed Login": 15,
    "Multiple Failed Logins": 35,
    "Suspicious DNS": 40,
    "File Integrity Change": 30,
    "Malware Alert": 70,
    "Privilege Escalation": 60,
    "Command and Control": 80
}


def calculate_severity(event_type):
    score = EVENT_SCORES.get(event_type, 10)

    if score >= 75:
        severity = "Critical"
    elif score >= 50:
        severity = "High"
    elif score >= 25:
        severity = "Medium"
    else:
        severity = "Low"

    return score, severity


def create_security_event(
    source,
    event_type,
    src_ip,
    dst_ip,
    description,
    asset_ip=None,
    timestamp=None
):
    score, severity = calculate_severity(event_type)

    event = normalize_event(
        source=source,
        event_type=event_type,
        severity=severity,
        src_ip=src_ip,
        dst_ip=dst_ip,
        description=description,
        timestamp=timestamp
    )

    event["risk_score"] = score
    event["asset_ip"] = asset_ip or dst_ip

    return event

if __name__ == "__main__":

    test_events = [
        {
            "source": "Suricata",
            "event_type": "Network Scan",
            "src_ip": "192.168.1.50",
            "dst_ip": "192.168.1.10",
            "description": "Possible reconnaissance activity"
        },

        {
            "source": "Wazuh",
            "event_type": "Multiple Failed Logins",
            "src_ip": "192.168.1.50",
            "dst_ip": "192.168.1.10",
            "description": "Repeated authentication failures"
        },

        {
            "source": "Zeek",
            "event_type": "Suspicious DNS",
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "description": "Unusual DNS communication detected"
        },

        {
            "source": "Suricata",
            "event_type": "Command and Control",
            "src_ip": "192.168.1.10",
            "dst_ip": "45.33.32.156",
            "description": "Possible command and control communication"
        }
    ]

    print("\n========== HomeSOC Security Events ==========\n")

    for raw_event in test_events:

        event = create_security_event(**raw_event)

        print(f"Source      : {event['source']}")
        print(f"Event       : {event['event_type']}")
        print(f"Source IP   : {event['src_ip']}")
        print(f"Destination : {event['dst_ip']}")
        print(f"Risk Score  : {event['risk_score']}")
        print(f"Severity    : {event['severity']}")
        print(f"Description : {event['description']}")
        print("-" * 45)