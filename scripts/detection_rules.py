
"""
HomeSOC Detection Engine v2

Rule: HOMESOC-AUTH-001

Detect repeated failed login attempts from the same
source IP against the same protected asset.

Features:
- Five-minute sliding window
- Source and asset isolation
- Duplicate log suppression
- Chronological event processing
- Repeated burst handling
"""

from collections import defaultdict, deque
from datetime import datetime, timezone


RULE_ID = "HOMESOC-AUTH-001"

DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_SECONDS = 300


def parse_event_time(timestamp):
    """Convert timestamps to timezone-aware UTC."""

    parsed = datetime.fromisoformat(
        str(timestamp).replace("Z", "+00:00")
    )

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def get_event_fingerprint(event, event_time):
    """
    Identify duplicate authentication log records.

    Prefer a source-provided event ID when available.
    Otherwise, compare normalized event fields.
    """

    source = event.get("source", "Unknown")
    event_id = event.get("event_id")

    if event_id is not None:
        return (
            "EVENT_ID",
            source,
            str(event_id)
        )

    return (
        "EVENT_FIELDS",
        source,
        event_time,
        event.get("event_type"),
        event.get("src_ip"),
        event.get("dst_ip"),
        event.get("asset_ip"),
        event.get("description"),
        event.get("risk_score")
    )


def detect_failed_login_bursts(
    events,
    threshold=DEFAULT_THRESHOLD,
    window_seconds=DEFAULT_WINDOW_SECONDS
):
    """
    Detect failed-login bursts using a sliding window.

    Five distinct failed-login records within 300
    seconds generate one detection by default.
    """

    if threshold < 2:
        raise ValueError(
            "Threshold must be at least 2."
        )

    if window_seconds <= 0:
        raise ValueError(
            "Window must be greater than zero."
        )

    grouped_events = defaultdict(list)
    seen_fingerprints = set()

    # ==========================================
    # FILTER AND DEDUPLICATE EVENTS
    # ==========================================

    for event in events:

        if event.get("event_type") != "Failed Login":
            continue

        source_ip = event.get("src_ip")

        asset_ip = (
            event.get("asset_ip")
            or event.get("dst_ip")
        )

        if not source_ip or not asset_ip:
            continue

        if not event.get("timestamp"):
            continue

        event_time = parse_event_time(
            event["timestamp"]
        )

        fingerprint = get_event_fingerprint(
            event,
            event_time
        )

        # Critical fix:
        # Ignore repeated copies of the same log.

        if fingerprint in seen_fingerprints:
            continue

        seen_fingerprints.add(fingerprint)

        grouped_events[
            (source_ip, asset_ip)
        ].append(
            (event_time, event)
        )

    detections = []

    # ==========================================
    # SLIDING WINDOW DETECTION
    # ==========================================

    for (source_ip, asset_ip), records in grouped_events.items():

        records.sort(
            key=lambda record: record[0]
        )

        window = deque()
        burst_active = False

        for event_time, event in records:

            # Remove events outside the window.

            while window and (
                event_time - window[0][0]
            ).total_seconds() > window_seconds:

                window.popleft()

            window.append(
                (event_time, event)
            )

            if len(window) < threshold:
                burst_active = False
                continue

            # Avoid repeated alerts during
            # the same continuous burst.

            if burst_active:
                continue

            burst_active = True

            first_seen = window[0][0]
            attempt_count = len(window)

            detection = {
                "timestamp": event["timestamp"],
                "source": "HomeSOC Rule Engine",
                "event_type": "Multiple Failed Logins",
                "severity": "Medium",
                "risk_score": 35,
                "src_ip": source_ip,
                "dst_ip": asset_ip,
                "asset_ip": asset_ip,
                "description": (
                    f"{RULE_ID}: Detected "
                    f"{attempt_count} distinct failed-login "
                    f"records from {source_ip} "
                    f"against {asset_ip} within "
                    f"{window_seconds} seconds."
                ),
                "rule_id": RULE_ID,
                "first_seen": first_seen.isoformat(),
                "attempt_count": attempt_count
            }

            detections.append(detection)

    detections.sort(
        key=lambda event: parse_event_time(
            event["timestamp"]
        )
    )

    return detections


# ==========================================
# STANDALONE VALIDATION
# ==========================================

if __name__ == "__main__":

    sample_events = []

    for minute in range(5):

        sample_events.append({
            "timestamp": (
                f"2026-10-16T18:{40 + minute}:00Z"
            ),
            "source": "Wazuh",
            "event_type": "Failed Login",
            "severity": "Low",
            "risk_score": 15,
            "src_ip": "192.168.1.50",
            "dst_ip": "192.168.1.20",
            "asset_ip": "192.168.1.20",
            "description": "Authentication failed"
        })

    results = detect_failed_login_bursts(
        sample_events
    )

    duplicates = [
        sample_events[0].copy()
        for _ in range(5)
    ]

    duplicate_results = detect_failed_login_bursts(
        duplicates
    )

    assert len(results) == 1
    assert len(duplicate_results) == 0

    print("\nHomeSOC Detection Engine v2")
    print("=" * 40)
    print(f"Rule: {RULE_ID}")
    print(f"Events analyzed: {len(sample_events)}")
    print(f"Detections generated: {len(results)}")
    print(
        f"Duplicate-only detections: "
        f"{len(duplicate_results)}"
    )
    print("\nVALIDATION PASSED")
