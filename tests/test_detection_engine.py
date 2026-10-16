
"""
HomeSOC Detection Engine Validation Suite

Tests:
- Multi-stage attack correlation
- Duplicate suppression
- Cross-source corroboration
- Correlation time windows
- Asset isolation
- Chronological ordering
- Severity thresholds
- MITRE ATT&CK mapping
- Confidence scoring

Run:
python -m unittest discover -s tests -v
"""

import sys
import unittest

from pathlib import Path
from datetime import datetime, timedelta


# ============================================
# IMPORT HOMESOC DETECTION MODULES
# ============================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


from correlation_engine import (
    correlate_events,
    calculate_incident_severity
)

from confidence_engine import (
    calculate_confidence,
    confidence_level
)

from mitre_mapping import (
    get_mitre_mapping,
    get_incident_mitre
)


# ============================================
# TEST EVENT FACTORY
# ============================================

BASE_TIME = datetime(
    2026, 10, 14, 18, 40, 0
)


def make_event(
    event_type,
    source="Suricata",
    risk_score=25,
    seconds=0,
    asset_ip="192.168.1.20"
):
    """
    Create a normalized synthetic security event.

    Test data only. No live traffic or
    production database interaction.
    """

    timestamp = (
        BASE_TIME + timedelta(seconds=seconds)
    ).isoformat(timespec="seconds")

    return {
        "timestamp": timestamp,
        "source": source,
        "event_type": event_type,
        "severity": "Medium",
        "risk_score": risk_score,
        "src_ip": "192.168.1.60",
        "dst_ip": asset_ip,
        "asset_ip": asset_ip,
        "description": f"Test event: {event_type}"
    }


# ============================================
# DETECTION VALIDATION TESTS
# ============================================

class TestHomeSOCDetectionEngine(unittest.TestCase):

    def test_01_multistage_attack(self):
        """
        Multiple attack stages should correlate
        into one critical incident.
        """

        events = [
            make_event(
                "Network Scan",
                "Suricata",
                25,
                0
            ),

            make_event(
                "Multiple Failed Logins",
                "Wazuh",
                35,
                120
            ),

            make_event(
                "Privilege Escalation",
                "Wazuh",
                60,
                240
            ),

            make_event(
                "Suspicious DNS",
                "Suricata",
                40,
                300
            ),

            make_event(
                "Command and Control",
                "Zeek",
                80,
                390
            )
        ]

        incidents = correlate_events(events)

        self.assertEqual(len(incidents), 1)

        incident = incidents[0]

        self.assertEqual(
            len(incident["events"]),
            5
        )

        self.assertEqual(
            incident["signal_count"],
            5
        )

        self.assertEqual(
            incident["total_score"],
            240
        )

        self.assertEqual(
            calculate_incident_severity(
                incident["total_score"]
            ),
            "CRITICAL"
        )

        self.assertEqual(
            incident["source_count"],
            3
        )

        self.assertEqual(
            len(incident["stages"]),
            4
        )


    def test_02_duplicate_suppression(self):
        """
        Repeated alerts from the same source
        within 90 seconds should not
        increase the incident risk score.
        """

        events = [
            make_event(
                "Network Scan",
                "Suricata",
                25,
                0
            ),

            make_event(
                "Network Scan",
                "Suricata",
                25,
                20
            )
        ]

        incident = correlate_events(events)[0]

        self.assertEqual(
            len(incident["events"]),
            2
        )

        self.assertEqual(
            incident["signal_count"],
            1
        )

        self.assertEqual(
            incident["suppressed_duplicates"],
            1
        )

        self.assertEqual(
            incident["total_score"],
            25
        )


    def test_03_cross_source_corroboration(self):
        """
        A second security tool reporting the
        same activity should add a bounded
        corroboration bonus.
        """

        events = [
            make_event(
                "Network Scan",
                "Suricata",
                25,
                0
            ),

            make_event(
                "Network Scan",
                "Zeek",
                25,
                15
            )
        ]

        incident = correlate_events(events)[0]

        # round(25 * 0.25) = 6

        self.assertEqual(
            incident["corroboration_bonus"],
            6
        )

        self.assertEqual(
            incident["total_score"],
            31
        )

        self.assertEqual(
            incident["signal_count"],
            1
        )

        self.assertEqual(
            incident["source_count"],
            2
        )


    def test_04_correlation_time_window(self):
        """
        Events more than 10 minutes apart
        from the previous event should
        start a new incident.
        """

        events = [
            make_event(
                "Network Scan",
                seconds=0
            ),

            make_event(
                "Failed Login",
                seconds=600
            ),

            make_event(
                "Suspicious DNS",
                seconds=1201
            )
        ]

        incidents = correlate_events(
            events,
            window_minutes=10
        )

        self.assertEqual(
            len(incidents),
            2
        )

        self.assertEqual(
            len(incidents[0]["events"]),
            2
        )

        self.assertEqual(
            len(incidents[1]["events"]),
            1
        )


    def test_05_asset_isolation(self):
        """
        Alerts affecting different assets
        must not merge into one incident.
        """

        events = [
            make_event(
                "Network Scan",
                seconds=0,
                asset_ip="192.168.1.20"
            ),

            make_event(
                "Network Scan",
                seconds=10,
                asset_ip="192.168.1.30"
            ),

            make_event(
                "Failed Login",
                seconds=20,
                asset_ip="192.168.1.20"
            )
        ]

        incidents = correlate_events(events)

        self.assertEqual(
            len(incidents),
            2
        )

        by_asset = {
            incident["asset_ip"]: incident
            for incident in incidents
        }

        self.assertEqual(
            len(by_asset["192.168.1.20"]["events"]),
            2
        )

        self.assertEqual(
            len(by_asset["192.168.1.30"]["events"]),
            1
        )


    def test_06_event_chronology(self):
        """
        Input order should not change
        chronological incident progression.
        """

        events = [
            make_event(
                "Privilege Escalation",
                risk_score=60,
                seconds=120
            ),

            make_event(
                "Network Scan",
                risk_score=25,
                seconds=0
            ),

            make_event(
                "Failed Login",
                risk_score=15,
                seconds=60
            )
        ]

        incident = correlate_events(events)[0]

        self.assertEqual(
            incident["events"][0]["event_type"],
            "Network Scan"
        )

        self.assertEqual(
            incident["events"][-1]["event_type"],
            "Privilege Escalation"
        )

        self.assertEqual(
            incident["stages"],
            [
                "Reconnaissance",
                "Credential Access",
                "Privilege Escalation"
            ]
        )


    def test_07_severity_thresholds(self):
        """
        Validate every incident severity
        threshold and its boundaries.
        """

        expected = {
            0: "LOW",
            39: "LOW",
            40: "MEDIUM",
            74: "MEDIUM",
            75: "HIGH",
            119: "HIGH",
            120: "CRITICAL",
            300: "CRITICAL"
        }

        for score, severity in expected.items():

            with self.subTest(score=score):

                self.assertEqual(
                    calculate_incident_severity(score),
                    severity
                )


    def test_08_mitre_mapping(self):
        """
        Validate known ATT&CK mappings and
        prevent unsupported technique claims.
        """

        scan = get_mitre_mapping(
            "Network Scan"
        )

        self.assertEqual(
            scan["technique_id"],
            "T1046"
        )

        privilege = get_mitre_mapping(
            "Privilege Escalation"
        )

        self.assertIsNone(
            privilege["technique_id"]
        )

        unknown = get_mitre_mapping(
            "Unrecognized Security Event"
        )

        self.assertIsNone(
            unknown["technique_id"]
        )

        events = [
            make_event("Network Scan"),
            make_event(
                "Network Scan",
                seconds=10
            )
        ]

        mappings = get_incident_mitre(events)

        self.assertEqual(
            len(mappings),
            1
        )


    def test_09_confidence_boundaries(self):
        """
        Confidence must remain bounded
        and use the correct labels.
        """

        expected = {
            0: "LOW",
            39: "LOW",
            40: "MEDIUM",
            69: "MEDIUM",
            70: "HIGH",
            84: "HIGH",
            85: "VERY HIGH",
            100: "VERY HIGH"
        }

        for score, level in expected.items():

            with self.subTest(score=score):

                self.assertEqual(
                    confidence_level(score),
                    level
                )

        synthetic_incident = {
            "events": [
                make_event(
                    "Network Scan",
                    source=f"Sensor-{i}"
                )
                for i in range(10)
            ],
            "signal_count": 999,
            "stages": [
                f"Stage-{i}"
                for i in range(30)
            ],
            "corroboration_bonus": 100,
            "suppressed_duplicates": 0
        }

        self.assertEqual(
            calculate_confidence(synthetic_incident),
            100
        )


    def test_10_empty_event_input(self):
        """
        No events should produce
        no incidents.
        """

        self.assertEqual(
            correlate_events([]),
            []
        )


# ============================================
# TEST RUNNER
# ============================================

if __name__ == "__main__":
    unittest.main()
