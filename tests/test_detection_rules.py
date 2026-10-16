
"""
HomeSOC Detection Engine v2
Authentication Detection Rule Validation

Rule: HOMESOC-AUTH-001
"""

import sys
import unittest

from pathlib import Path
from datetime import datetime, timedelta, timezone


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from detection_rules import detect_failed_login_bursts


BASE_TIME = datetime(
    2026, 10, 16, 18, 0, 0,
    tzinfo=timezone.utc
)


def make_event(
    seconds,
    source_ip="192.168.1.50",
    asset_ip="192.168.1.20"
):
    timestamp = (
        BASE_TIME + timedelta(seconds=seconds)
    ).isoformat()

    return {
        "timestamp": timestamp,
        "source": "Wazuh",
        "event_type": "Failed Login",
        "severity": "Low",
        "risk_score": 15,
        "src_ip": source_ip,
        "dst_ip": asset_ip,
        "asset_ip": asset_ip,
        "description": "Authentication failed"
    }


class TestAuthenticationDetection(unittest.TestCase):

    def test_01_benign_activity(self):
        """Four failed logins should not trigger."""

        events = [
            make_event(0),
            make_event(60),
            make_event(120),
            make_event(180)
        ]

        results = detect_failed_login_bursts(events)

        self.assertEqual(len(results), 0)


    def test_02_five_failed_logins(self):
        """Five failures within 300 seconds should trigger."""

        events = [
            make_event(0),
            make_event(60),
            make_event(120),
            make_event(180),
            make_event(240)
        ]

        results = detect_failed_login_bursts(events)

        self.assertEqual(len(results), 1)
        self.assertEqual(
            results[0]["rule_id"],
            "HOMESOC-AUTH-001"
        )
        self.assertEqual(
            results[0]["attempt_count"],
            5
        )


    def test_03_source_ip_isolation(self):
        """Failures from different IPs must remain separate."""

        events = [
            make_event(0, "192.168.1.50"),
            make_event(30, "192.168.1.50"),
            make_event(60, "192.168.1.50"),
            make_event(90, "192.168.1.60"),
            make_event(120, "192.168.1.60")
        ]

        results = detect_failed_login_bursts(events)

        self.assertEqual(len(results), 0)


    def test_04_asset_isolation(self):
        """Failures against different assets must remain separate."""

        events = [
            make_event(0, asset_ip="192.168.1.20"),
            make_event(30, asset_ip="192.168.1.20"),
            make_event(60, asset_ip="192.168.1.20"),
            make_event(90, asset_ip="192.168.1.30"),
            make_event(120, asset_ip="192.168.1.30")
        ]

        results = detect_failed_login_bursts(events)

        self.assertEqual(len(results), 0)


    def test_05_exact_window_boundary(self):
        """A 300-second boundary should count."""

        events = [
            make_event(0),
            make_event(75),
            make_event(150),
            make_event(225),
            make_event(300)
        ]

        results = detect_failed_login_bursts(events)

        self.assertEqual(len(results), 1)


    def test_06_outside_time_window(self):
        """Five events spanning more than 300 seconds should not trigger."""

        events = [
            make_event(0),
            make_event(75),
            make_event(150),
            make_event(225),
            make_event(301)
        ]

        results = detect_failed_login_bursts(events)

        self.assertEqual(len(results), 0)


    def test_07_unsorted_events(self):
        """Out-of-order events should still trigger correctly."""

        events = [
            make_event(240),
            make_event(0),
            make_event(180),
            make_event(60),
            make_event(120)
        ]

        results = detect_failed_login_bursts(events)

        self.assertEqual(len(results), 1)


    def test_08_duplicate_log_records(self):
        """Five copies of one record must not trigger an alert."""

        original = make_event(0)

        events = [
            original.copy()
            for _ in range(5)
        ]

        results = detect_failed_login_bursts(events)

        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    unittest.main()
