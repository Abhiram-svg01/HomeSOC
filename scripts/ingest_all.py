
"""
HomeSOC Unified Security Ingestion

Supported sources:
- Suricata
- Zeek
- Wazuh
- AuthLab (optional simulated authentication telemetry)

Default:
    python scripts/ingest_all.py

With authentication lab:
    python scripts/ingest_all.py --auth-lab
"""

import argparse
import sqlite3

from pathlib import Path
from datetime import datetime, timezone
from contextlib import closing

from parsers.suricata_parser import load_suricata_eve
from parsers.zeek_parser import load_zeek_notices
from parsers.wazuh_parser import load_wazuh_alerts

from correlation_engine import (
    correlate_events,
    print_incident
)

from database import (
    init_database,
    save_incident
)

from auth_lab_loader import load_auth_lab_detections


# ==========================================
# PROJECT PATHS
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATABASE_PATH = (
    PROJECT_ROOT / "data" / "homesoc.db"
)

SURICATA_LOG = str(
    PROJECT_ROOT / "sample-logs" / "suricata_eve.jsonl"
)

ZEEK_LOG = str(
    PROJECT_ROOT / "sample-logs" / "zeek_notice.jsonl"
)

WAZUH_LOG = str(
    PROJECT_ROOT / "sample-logs" / "wazuh_alerts.jsonl"
)


def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds")


# ==========================================
# INGESTION HEALTH TRACKING
# ==========================================

def start_ingestion_run():

    with closing(
        sqlite3.connect(DATABASE_PATH)
    ) as connection:

        with connection:

            connection.execute("""
                CREATE TABLE IF NOT EXISTS ingestion_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT NOT NULL,
                    suricata_events INTEGER DEFAULT 0,
                    zeek_events INTEGER DEFAULT 0,
                    wazuh_events INTEGER DEFAULT 0,
                    normalized_events INTEGER DEFAULT 0,
                    incidents_correlated INTEGER DEFAULT 0,
                    error_message TEXT,
                    auth_lab_records INTEGER DEFAULT 0,
                    auth_lab_detections INTEGER DEFAULT 0
                )
            """)

            # Migrate existing HomeSOC databases
            # without removing previous ingestion history.

            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(ingestion_runs)"
                ).fetchall()
            }

            if "auth_lab_records" not in columns:
                connection.execute("""
                    ALTER TABLE ingestion_runs
                    ADD COLUMN auth_lab_records
                    INTEGER DEFAULT 0
                """)

            if "auth_lab_detections" not in columns:
                connection.execute("""
                    ALTER TABLE ingestion_runs
                    ADD COLUMN auth_lab_detections
                    INTEGER DEFAULT 0
                """)

            cursor = connection.execute("""
                INSERT INTO ingestion_runs (
                    started_at,
                    status
                )
                VALUES (?, ?)
            """, (
                utc_now(),
                "RUNNING"
            ))

            return cursor.lastrowid


def finish_ingestion_run(
    run_id,
    status,
    counts,
    incident_count,
    error_message=None
):

    with closing(
        sqlite3.connect(DATABASE_PATH)
    ) as connection:

        with connection:

            connection.execute("""
                UPDATE ingestion_runs
                SET
                    completed_at = ?,
                    status = ?,
                    suricata_events = ?,
                    zeek_events = ?,
                    wazuh_events = ?,
                    normalized_events = ?,
                    incidents_correlated = ?,
                    error_message = ?,
                    auth_lab_records = ?,
                    auth_lab_detections = ?
                WHERE id = ?
            """, (
                utc_now(),
                status,
                counts["suricata"],
                counts["zeek"],
                counts["wazuh"],
                counts["total"],
                incident_count,
                error_message,
                counts["auth_lab_records"],
                counts["auth_lab_detections"],
                run_id
            ))


# ==========================================
# MAIN INGESTION PIPELINE
# ==========================================

def main():

    parser = argparse.ArgumentParser(
        description="HomeSOC Unified Security Ingestion"
    )

    parser.add_argument(
        "--auth-lab",
        action="store_true",
        help=(
            "Include simulated authentication "
            "rule detections"
        )
    )

    args = parser.parse_args()

    print("\nHomeSOC Unified Security Ingestion")
    print("=" * 55)

    if args.auth_lab:
        print("Mode: AUTHENTICATION LAB ENABLED")
    else:
        print("Mode: STANDARD INGESTION")

    init_database()

    run_id = start_ingestion_run()

    counts = {
        "suricata": 0,
        "zeek": 0,
        "wazuh": 0,
        "auth_lab_records": 0,
        "auth_lab_detections": 0,
        "total": 0
    }

    incident_count = 0

    print(f"Ingestion Run ID : {run_id}")
    print(f"Started (UTC)    : {utc_now()}")

    try:

        # ======================================
        # LOAD STANDARD SECURITY TELEMETRY
        # ======================================

        suricata_events = load_suricata_eve(
            SURICATA_LOG
        )

        zeek_events = load_zeek_notices(
            ZEEK_LOG
        )

        wazuh_events = load_wazuh_alerts(
            WAZUH_LOG
        )

        counts["suricata"] = len(
            suricata_events
        )

        counts["zeek"] = len(
            zeek_events
        )

        counts["wazuh"] = len(
            wazuh_events
        )

        print("\nSecurity Sources")
        print("-" * 55)

        print(
            f"Suricata events : {counts['suricata']}"
        )

        print(
            f"Zeek events     : {counts['zeek']}"
        )

        print(
            f"Wazuh events    : {counts['wazuh']}"
        )

        # ======================================
        # BUILD NORMALIZED EVENT COLLECTION
        # ======================================

        all_events = (
            suricata_events
            + zeek_events
            + wazuh_events
        )

        # ======================================
        # OPTIONAL AUTHENTICATION LAB
        # ======================================

        if args.auth_lab:

            print("\nAuthentication Detection Lab")
            print("-" * 55)

            auth_records, auth_detections = (
                load_auth_lab_detections()
            )

            counts["auth_lab_records"] = len(
                auth_records
            )

            counts["auth_lab_detections"] = len(
                auth_detections
            )

            print(
                "Authentication log records : "
                f"{counts['auth_lab_records']}"
            )

            print(
                "HOMESOC-AUTH-001 detections: "
                f"{counts['auth_lab_detections']}"
            )

            # Only forward the derived detection.
            #
            # Individual failed-login records
            # are not forwarded separately,
            # preventing duplicate risk scoring.

            all_events.extend(
                auth_detections
            )

        counts["total"] = len(
            all_events
        )

        print("\nUnified Event Collection")
        print("-" * 55)

        print(
            "Total normalized events forwarded: "
            f"{counts['total']}"
        )

        # ======================================
        # INCIDENT CORRELATION
        # ======================================

        incidents = correlate_events(
            all_events,
            window_minutes=10
        )

        incident_count = len(
            incidents
        )

        print(
            f"\nGenerated {incident_count} "
            "correlated incident(s)."
        )

        # ======================================
        # STORE INCIDENTS
        # ======================================

        for number, incident in enumerate(
            incidents,
            start=1
        ):

            print_incident(
                incident,
                incident_number=number
            )

            incident_id = save_incident(
                incident
            )

            print(
                "Stored as HomeSOC incident "
                f"#{incident_id:04d}"
            )

        # ======================================
        # MARK INGESTION SUCCESS
        # ======================================

        finish_ingestion_run(
            run_id=run_id,
            status="SUCCESS",
            counts=counts,
            incident_count=incident_count
        )

        print("\n" + "=" * 55)

        print("HomeSOC Ingestion Status : SUCCESS")

        print(
            f"Ingestion Run ID        : {run_id}"
        )

        print(
            f"Events Forwarded        : {counts['total']}"
        )

        print(
            f"Incidents Correlated    : {incident_count}"
        )

        if args.auth_lab:

            print(
                "AuthLab Rule Detections  : "
                f"{counts['auth_lab_detections']}"
            )

        print(
            f"Completed (UTC)         : {utc_now()}"
        )

        print("=" * 55)

    except Exception as error:

        finish_ingestion_run(
            run_id=run_id,
            status="FAILED",
            counts=counts,
            incident_count=incident_count,
            error_message=str(error)
        )

        print("\nHomeSOC Ingestion Status : FAILED")
        print(f"Reason: {error}")

        raise


if __name__ == "__main__":
    main()
