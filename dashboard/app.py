
import sqlite3
import sys

from io import BytesIO
from pathlib import Path
from datetime import datetime, timezone

from flask import (
    Flask,
    render_template,
    abort,
    request,
    redirect,
    url_for,
    send_file
)


# ==================================================
# PROJECT CONFIGURATION
# ==================================================

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from mitre_mapping import get_incident_mitre
from report_generator import build_incident_pdf


app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates")
)

DB_PATH = PROJECT_ROOT / "data" / "homesoc.db"


ATTACK_STAGES = {
    "Network Scan": "Reconnaissance",
    "Failed Login": "Credential Access",
    "Multiple Failed Logins": "Credential Access",
    "Privilege Escalation": "Privilege Escalation",
    "File Integrity Change": "System Modification",
    "Malware Alert": "Execution",
    "Suspicious DNS": "Command and Control",
    "Command and Control": "Command and Control"
}


VALID_STATUSES = {
    "NEW",
    "INVESTIGATING",
    "RESOLVED"
}


# ==================================================
# DATABASE CONNECTION
# ==================================================

def get_db_connection():

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    return connection


# ==================================================
# SYSTEM HEALTH HELPERS
# ==================================================

def parse_utc_timestamp(value):

    if not value:
        return None

    try:
        timestamp = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(
                tzinfo=timezone.utc
            )

        return timestamp.astimezone(timezone.utc)

    except (ValueError, TypeError):
        return None


def format_utc_timestamp(value):

    timestamp = parse_utc_timestamp(value)

    if timestamp is None:
        return "Not available"

    return timestamp.strftime(
        "%b %d, %Y at %I:%M %p UTC"
    )


def format_elapsed_time(seconds):

    if seconds is None:
        return "Not available"

    seconds = max(0, int(seconds))

    if seconds < 60:
        return "Just now"

    minutes = seconds // 60

    if minutes < 60:
        return f"{minutes} min ago"

    hours = minutes // 60

    if hours < 24:
        return f"{hours} hr ago"

    days = hours // 24

    return f"{days} day(s) ago"


# ==================================================
# INGESTION HEALTH
# ==================================================

def get_ingestion_health(connection):

    health = {
        "status": "NOT_STARTED",
        "status_label": "Never Run",
        "run_id": None,
        "last_run_at": "Never",
        "last_success_at": "Never",
        "last_success_age": "No successful run yet",
        "freshness": "UNKNOWN",
        "events_processed": 0,
        "incidents_correlated": 0,
        "suricata_events": 0,
        "zeek_events": 0,
        "wazuh_events": 0,
        "error_message": None,
        "data_mode": "SAMPLE LOGS"
    }

    table_exists = connection.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name = 'ingestion_runs'
    """).fetchone()

    if table_exists is None:
        return health

    latest_run = connection.execute("""
        SELECT *
        FROM ingestion_runs
        ORDER BY id DESC
        LIMIT 1
    """).fetchone()

    if latest_run is None:
        return health

    run_status = latest_run["status"] or "UNKNOWN"

    status_labels = {
        "SUCCESS": "Successful",
        "FAILED": "Failed",
        "RUNNING": "Running"
    }

    latest_timestamp = (
        latest_run["completed_at"]
        or latest_run["started_at"]
    )

    health["status"] = run_status

    health["status_label"] = status_labels.get(
        run_status,
        "Unknown"
    )

    health["run_id"] = latest_run["id"]

    health["last_run_at"] = format_utc_timestamp(
        latest_timestamp
    )

    health["events_processed"] = (
        latest_run["normalized_events"] or 0
    )

    health["incidents_correlated"] = (
        latest_run["incidents_correlated"] or 0
    )

    health["suricata_events"] = (
        latest_run["suricata_events"] or 0
    )

    health["zeek_events"] = (
        latest_run["zeek_events"] or 0
    )

    health["wazuh_events"] = (
        latest_run["wazuh_events"] or 0
    )

    health["error_message"] = (
        latest_run["error_message"]
    )

    last_success = connection.execute("""
        SELECT completed_at
        FROM ingestion_runs
        WHERE status = 'SUCCESS'
          AND completed_at IS NOT NULL
        ORDER BY id DESC
        LIMIT 1
    """).fetchone()

    if last_success is None:
        return health

    completed_at = last_success["completed_at"]

    health["last_success_at"] = (
        format_utc_timestamp(completed_at)
    )

    parsed_time = parse_utc_timestamp(
        completed_at
    )

    if parsed_time is None:
        return health

    elapsed_seconds = max(
        0,
        int(
            (
                datetime.now(timezone.utc)
                - parsed_time
            ).total_seconds()
        )
    )

    health["last_success_age"] = (
        format_elapsed_time(elapsed_seconds)
    )

    # Freshness measures ingestion activity,
    # not the age of the sample log events.

    if elapsed_seconds <= 3600:
        health["freshness"] = "RECENT"
    else:
        health["freshness"] = "STALE"

    return health


# ==================================================
# INCIDENT HELPERS
# ==================================================

def load_incident_and_events(incident_id):

    connection = get_db_connection()

    try:
        incident = connection.execute(
            """
            SELECT *
            FROM incidents
            WHERE id = ?
            """,
            (incident_id,)
        ).fetchone()

        if incident is None:
            return None, []

        events = connection.execute(
            """
            SELECT *
            FROM events
            WHERE incident_id = ?
            ORDER BY timestamp ASC
            """,
            (incident_id,)
        ).fetchall()

        return incident, events

    finally:
        connection.close()


def get_attack_progression(events):

    attack_progression = []

    for event in events:

        stage = ATTACK_STAGES.get(
            event["event_type"],
            "Unknown"
        )

        if stage not in attack_progression:
            attack_progression.append(stage)

    return attack_progression


# ==================================================
# MAIN DASHBOARD
# ==================================================

@app.route("/")
def dashboard():

    severity_filter = request.args.get(
        "severity",
        ""
    ).strip().upper()

    search_query = request.args.get(
        "search",
        ""
    ).strip()

    query = """
        SELECT *
        FROM incidents
        WHERE 1 = 1
    """

    params = []

    if severity_filter:

        query += """
            AND severity = ?
        """

        params.append(severity_filter)

    if search_query:

        cleaned_search = (
            search_query
            .replace("#", "")
            .strip()
        )

        if cleaned_search.isdigit():

            query += """
                AND (
                    id = ?
                    OR asset_ip LIKE ?
                    OR sources LIKE ?
                )
            """

            params.extend([
                int(cleaned_search),
                f"%{search_query}%",
                f"%{search_query}%"
            ])

        else:

            query += """
                AND (
                    asset_ip LIKE ?
                    OR sources LIKE ?
                )
            """

            params.extend([
                f"%{search_query}%",
                f"%{search_query}%"
            ])

    query += """
        ORDER BY id DESC
    """

    connection = get_db_connection()

    try:

        incidents = connection.execute(
            query,
            params
        ).fetchall()

        # ------------------------------------------
        # SECURITY OVERVIEW
        # ------------------------------------------

        total_incidents = connection.execute("""
            SELECT COUNT(*) AS count
            FROM incidents
        """).fetchone()["count"]

        critical_incidents = connection.execute("""
            SELECT COUNT(*) AS count
            FROM incidents
            WHERE severity = 'CRITICAL'
        """).fetchone()["count"]

        protected_assets = connection.execute("""
            SELECT COUNT(DISTINCT asset_ip) AS count
            FROM incidents
        """).fetchone()["count"]

        average_risk = connection.execute("""
            SELECT AVG(total_score) AS average
            FROM incidents
        """).fetchone()["average"]

        # ------------------------------------------
        # CORRELATION INTELLIGENCE
        # ------------------------------------------

        total_raw_events = connection.execute("""
            SELECT COALESCE(
                SUM(event_count),
                0
            ) AS total
            FROM incidents
        """).fetchone()["total"]

        total_unique_signals = connection.execute("""
            SELECT COALESCE(
                SUM(signal_count),
                0
            ) AS total
            FROM incidents
        """).fetchone()["total"]

        total_duplicates_suppressed = (
            connection.execute("""
                SELECT COALESCE(
                    SUM(suppressed_duplicates),
                    0
                ) AS total
                FROM incidents
            """).fetchone()["total"]
        )

        total_corroboration_bonus = (
            connection.execute("""
                SELECT COALESCE(
                    SUM(corroboration_bonus),
                    0
                ) AS total
                FROM incidents
            """).fetchone()["total"]
        )

        # ------------------------------------------
        # INGESTION SYSTEM HEALTH
        # ------------------------------------------

        ingestion_health = get_ingestion_health(
            connection
        )

    finally:
        connection.close()

    if average_risk is None:
        average_risk = 0

    average_risk = round(
        average_risk,
        1
    )

    return render_template(
        "dashboard.html",

        incidents=incidents,

        total_incidents=total_incidents,
        critical_incidents=critical_incidents,
        protected_assets=protected_assets,
        average_risk=average_risk,

        total_raw_events=total_raw_events,
        total_unique_signals=total_unique_signals,

        total_duplicates_suppressed=(
            total_duplicates_suppressed
        ),

        total_corroboration_bonus=(
            total_corroboration_bonus
        ),

        ingestion_health=ingestion_health,

        severity_filter=severity_filter,
        search_query=search_query
    )


# ==================================================
# INCIDENT INVESTIGATION PAGE
# ==================================================

@app.route("/incident/<int:incident_id>")
def incident_details(incident_id):

    incident, events = load_incident_and_events(
        incident_id
    )

    if incident is None:
        abort(404)

    attack_progression = get_attack_progression(
        events
    )

    mitre_techniques = get_incident_mitre(
        events
    )

    return render_template(
        "incident.html",

        incident=incident,
        events=events,

        attack_progression=attack_progression,
        mitre_techniques=mitre_techniques
    )


# ==================================================
# ANALYST STATUS WORKFLOW
# ==================================================

@app.route(
    "/incident/<int:incident_id>/status",
    methods=["POST"]
)
def update_incident_status(incident_id):

    new_status = request.form.get(
        "status",
        ""
    ).strip().upper()

    if new_status not in VALID_STATUSES:
        abort(400)

    connection = get_db_connection()

    try:

        cursor = connection.execute(
            """
            UPDATE incidents
            SET status = ?
            WHERE id = ?
            """,
            (
                new_status,
                incident_id
            )
        )

        if cursor.rowcount == 0:
            connection.rollback()
            abort(404)

        connection.commit()

    finally:
        connection.close()

    return redirect(
        url_for(
            "incident_details",
            incident_id=incident_id
        )
    )


# ==================================================
# PDF INCIDENT REPORT EXPORT
# ==================================================

@app.route("/incident/<int:incident_id>/report")
def download_incident_report(incident_id):

    incident, events = load_incident_and_events(
        incident_id
    )

    if incident is None:
        abort(404)

    attack_progression = get_attack_progression(
        events
    )

    mitre_techniques = get_incident_mitre(
        events
    )

    # Generate the PDF entirely in memory.

    pdf_bytes = build_incident_pdf(
        incident=incident,
        events=events,
        mitre_techniques=mitre_techniques,
        attack_progression=attack_progression
    )

    filename = (
        f"HomeSOC_Incident_{incident_id:04d}_Report.pdf"
    )

    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename
    )


# ==================================================
# APPLICATION STARTUP
# ==================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )
