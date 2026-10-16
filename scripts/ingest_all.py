
from pathlib import Path
from datetime import datetime, timezone
from contextlib import closing
import sqlite3

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


# --------------------------------------------------
# PROJECT PATHS
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATABASE_PATH = PROJECT_ROOT / "data" / "homesoc.db"

SURICATA_LOG = str(
    PROJECT_ROOT / "sample-logs" / "suricata_eve.jsonl"
)

ZEEK_LOG = str(
    PROJECT_ROOT / "sample-logs" / "zeek_notice.jsonl"
)

WAZUH_LOG = str(
    PROJECT_ROOT / "sample-logs" / "wazuh_alerts.jsonl"
)


# --------------------------------------------------
# INGESTION MONITORING
# --------------------------------------------------

def utc_now():
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )


def start_ingestion_run():

    with closing(sqlite3.connect(DATABASE_PATH)) as conn:
        with conn:

            conn.execute("""
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
                    error_message TEXT
                )
            """)

            cursor = conn.execute("""
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

    with closing(sqlite3.connect(DATABASE_PATH)) as conn:
        with conn:

            conn.execute("""
                UPDATE ingestion_runs
                SET
                    completed_at = ?,
                    status = ?,
                    suricata_events = ?,
                    zeek_events = ?,
                    wazuh_events = ?,
                    normalized_events = ?,
                    incidents_correlated = ?,
                    error_message = ?
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
                run_id
            ))


# --------------------------------------------------
# MAIN INGESTION PIPELINE
# --------------------------------------------------

def main():

    print("\nHomeSOC Unified Security Ingestion")
    print("-" * 50)

    init_database()

    run_id = start_ingestion_run()

    counts = {
        "suricata": 0,
        "zeek": 0,
        "wazuh": 0,
        "total": 0
    }

    incident_count = 0

    print(f"Ingestion Run ID : {run_id}")
    print(f"Started (UTC)    : {utc_now()}")

    try:

        # ------------------------------------------
        # LOAD SECURITY EVENTS
        # ------------------------------------------

        suricata_events = load_suricata_eve(
            SURICATA_LOG
        )

        zeek_events = load_zeek_notices(
            ZEEK_LOG
        )

        wazuh_events = load_wazuh_alerts(
            WAZUH_LOG
        )

        counts["suricata"] = len(suricata_events)
        counts["zeek"] = len(zeek_events)
        counts["wazuh"] = len(wazuh_events)

        print(
            f"\nSuricata events : {counts['suricata']}"
        )

        print(
            f"Zeek events     : {counts['zeek']}"
        )

        print(
            f"Wazuh events    : {counts['wazuh']}"
        )

        # ------------------------------------------
        # NORMALIZE EVENT COLLECTION
        # ------------------------------------------

        all_events = (
            suricata_events
            + zeek_events
            + wazuh_events
        )

        counts["total"] = len(all_events)

        print(
            f"\nTotal normalized events: "
            f"{counts['total']}"
        )

        # ------------------------------------------
        # CORRELATE EVENTS
        # ------------------------------------------

        incidents = correlate_events(
            all_events,
            window_minutes=10
        )

        incident_count = len(incidents)

        print(
            f"Generated {incident_count} "
            f"correlated incident(s)."
        )

        # ------------------------------------------
        # STORE INCIDENTS
        # ------------------------------------------

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
                f"Stored as HomeSOC "
                f"incident #{incident_id:04d}"
            )

        # ------------------------------------------
        # MARK INGESTION SUCCESS
        # ------------------------------------------

        finish_ingestion_run(
            run_id=run_id,
            status="SUCCESS",
            counts=counts,
            incident_count=incident_count
        )

        print("\n" + "-" * 50)
        print("HomeSOC Ingestion Status : SUCCESS")
        print(f"Ingestion Run ID        : {run_id}")
        print(f"Events Processed        : {counts['total']}")
        print(f"Incidents Correlated    : {incident_count}")
        print(f"Completed (UTC)         : {utc_now()}")
        print("-" * 50)

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
