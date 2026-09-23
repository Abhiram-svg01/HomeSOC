from datetime import datetime


def normalize_event(source, event_type, severity, src_ip, dst_ip, description):
    """
    Convert security events from different tools into
    one common HomeSOC event format.
    """

    event = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "source": source,
        "event_type": event_type,
        "severity": severity,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "description": description
    }

    return event


if __name__ == "__main__":

    test_event = normalize_event(
        source="Suricata",
        event_type="Network Scan",
        severity="Medium",
        src_ip="192.168.1.50",
        dst_ip="192.168.1.10",
        description="Possible network reconnaissance detected"
    )

    print("\nHomeSOC Normalized Security Event\n")

    for key, value in test_event.items():
        print(f"{key:12}: {value}")