MITRE_MAPPING = {
    "Network Scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery"
    },

    "Failed Login": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access"
    },

    "Multiple Failed Logins": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing",
        "tactic": "Credential Access"
    },

    "Suspicious DNS": {
        "technique_id": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control"
    },

    "Command and Control": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control"
    },

    # These event labels are too broad to map safely
    # to one specific ATT&CK technique without more context.
    "Privilege Escalation": {
        "technique_id": None,
        "technique_name": "Context-dependent",
        "tactic": "Privilege Escalation"
    },

    "File Integrity Change": {
        "technique_id": None,
        "technique_name": "Context-dependent",
        "tactic": "Defense Evasion / Persistence"
    },

    "Malware Alert": {
        "technique_id": None,
        "technique_name": "Context-dependent",
        "tactic": "Execution"
    }
}


def get_mitre_mapping(event_type):
    """
    Return MITRE ATT&CK metadata for a HomeSOC event type.
    """

    return MITRE_MAPPING.get(
        event_type,
        {
            "technique_id": None,
            "technique_name": "Unmapped",
            "tactic": "Unknown"
        }
    )


def get_incident_mitre(events):
    """
    Build a unique list of ATT&CK mappings represented
    inside a correlated HomeSOC incident.
    """

    techniques = []
    seen = set()

    for event in events:
        mapping = get_mitre_mapping(
            event["event_type"]
        )

        key = (
            mapping["technique_id"],
            mapping["technique_name"],
            mapping["tactic"]
        )

        if key in seen:
            continue

        seen.add(key)

        techniques.append({
            "event_type": event["event_type"],
            "technique_id": mapping["technique_id"],
            "technique_name": mapping["technique_name"],
            "tactic": mapping["tactic"]
        })

    return techniques
