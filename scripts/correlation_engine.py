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


# Events of the same type occurring within this period
# are treated as possible observations of the same activity.
DEDUP_WINDOW_SECONDS = 90

# Different tools confirming the same activity increase confidence,
# but should not add the entire event score again.
CORROBORATION_PERCENT = 0.25
CORROBORATION_CAP = 15


def parse_timestamp(timestamp):
    timestamp = timestamp.replace(
        "Z",
        "+00:00"
    )

    return datetime.fromisoformat(
        timestamp
    )


def find_matching_signal(
    incident,
    event,
    event_time
):
    for signal in reversed(
        incident["_signal_groups"]
    ):

        if (
            signal["event_type"]
            != event["event_type"]
        ):
            continue

        signal_time = parse_timestamp(
            signal["last_time"]
        )

        difference = (
            event_time - signal_time
        ).total_seconds()

        if (
            0
            <= difference
            <= DEDUP_WINDOW_SECONDS
        ):
            return signal

    return None


def score_event(
    incident,
    event,
    event_time
):
    """
    Add risk without blindly double-counting duplicate alerts.
    """

    signal = find_matching_signal(
        incident,
        event,
        event_time
    )

    if signal is None:

        incident["total_score"] += (
            event["risk_score"]
        )

        incident["_signal_groups"].append(
            {
                "event_type": event["event_type"],
                "base_score": event["risk_score"],
                "last_time": event["timestamp"],
                "sources": {
                    event["source"]
                }
            }
        )

        return

    # Same activity reported again.
    signal["last_time"] = event["timestamp"]

    # Same tool reporting the same activity again:
    # keep the evidence, but don't increase risk.
    if event["source"] in signal["sources"]:

        incident[
            "suppressed_duplicates"
        ] += 1

        return

    # A different security tool corroborated the event.
    bonus = round(
        signal["base_score"]
        * CORROBORATION_PERCENT
    )

    bonus = min(
        bonus,
        CORROBORATION_CAP
    )

    incident["total_score"] += bonus
    incident["corroboration_bonus"] += bonus

    signal["sources"].add(
        event["source"]
    )


def correlate_events(
    events,
    window_minutes=10
):
    correlation_window = timedelta(
        minutes=window_minutes
    )

    events = sorted(
        events,
        key=lambda event: parse_timestamp(
            event["timestamp"]
        )
    )

    incidents = []

    for event in events:

        event_time = parse_timestamp(
            event["timestamp"]
        )

        asset = event["asset_ip"]

        matching_incident = None

        for incident in reversed(
            incidents
        ):

            if (
                incident["asset_ip"]
                != asset
            ):
                continue

            last_time = parse_timestamp(
                incident["events"][-1][
                    "timestamp"
                ]
            )

            if (
                event_time - last_time
                <= correlation_window
            ):
                matching_incident = (
                    incident
                )

            break

        if matching_incident is None:

            matching_incident = {
                "asset_ip": asset,
                "events": [],
                "total_score": 0,
                "stages": [],
                "start_time": event[
                    "timestamp"
                ],
                "end_time": event[
                    "timestamp"
                ],
                "corroboration_bonus": 0,
                "suppressed_duplicates": 0,
                "_signal_groups": []
            }

            incidents.append(
                matching_incident
            )

        matching_incident[
            "events"
        ].append(event)

        matching_incident[
            "end_time"
        ] = event["timestamp"]

        score_event(
            matching_incident,
            event,
            event_time
        )

        stage = ATTACK_STAGES.get(
            event["event_type"],
            "Unknown"
        )

        if (
            stage
            not in matching_incident[
                "stages"
            ]
        ):
            matching_incident[
                "stages"
            ].append(stage)

    # Preserve useful signal counts but remove
    # internal correlation structures.
    for incident in incidents:

        incident["signal_count"] = len(
            incident["_signal_groups"]
        )

        incident.pop(
            "_signal_groups",
            None
        )

    return incidents


def calculate_incident_severity(score):

    if score >= 120:
        return "CRITICAL"

    if score >= 75:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


def print_incident(
    incident,
    incident_number=None
):

    severity = (
        calculate_incident_severity(
            incident["total_score"]
        )
    )

    print("\n" + "=" * 55)

    if incident_number:

        print(
            f"HOMESOC INCIDENT "
            f"#{incident_number:04d}"
        )

    else:

        print(
            "HOMESOC INCIDENT"
        )

    print("=" * 55)

    print(
        f"Protected Asset : "
        f"{incident['asset_ip']}"
    )

    print(
        f"Start Time      : "
        f"{incident['start_time']}"
    )

    print(
        f"End Time        : "
        f"{incident['end_time']}"
    )

    print(
        f"Raw Events      : "
        f"{len(incident['events'])}"
    )

    print(
        f"Unique Signals  : "
        f"{incident.get('signal_count', 0)}"
    )

    print(
        f"Incident Score  : "
        f"{incident['total_score']}"
    )

    print(
        f"Severity        : "
        f"{severity}"
    )

    print(
        f"Cross-tool Bonus: "
        f"{incident.get('corroboration_bonus', 0)}"
    )

    print(
        f"Duplicates Suppressed: "
        f"{incident.get('suppressed_duplicates', 0)}"
    )

    print("\nAttack Progression:")

    print(
        " -> ".join(
            incident["stages"]
        )
    )

    print("\nEvidence:")

    for event in incident["events"]:

        print(
            f"{event['timestamp']} | "
            f"[{event['source']}] "
            f"{event['event_type']} "
            f"({event['risk_score']} points)"
        )

    if len(
        incident["stages"]
    ) >= 3:

        print(
            "\nAssessment: Possible "
            "multi-stage attack detected."
        )

    print("=" * 55)