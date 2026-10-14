import sqlite3
import sys
from pathlib import Path

from flask import (
    Flask,
    render_template,
    abort,
    request,
    redirect,
    url_for
)


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(
        0,
        str(SCRIPTS_DIR)
    )

from mitre_mapping import get_incident_mitre


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


def get_db_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    return connection


@app.route("/")
def dashboard():
    connection = get_db_connection()

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

        params.append(
            severity_filter
        )

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

    incidents = connection.execute(
        query,
        params
    ).fetchall()

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

    total_duplicates_suppressed = connection.execute("""
        SELECT COALESCE(
            SUM(suppressed_duplicates),
            0
        ) AS total
        FROM incidents
    """).fetchone()["total"]

    total_corroboration_bonus = connection.execute("""
        SELECT COALESCE(
            SUM(corroboration_bonus),
            0
        ) AS total
        FROM incidents
    """).fetchone()["total"]

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

        severity_filter=severity_filter,
        search_query=search_query
    )


@app.route(
    "/incident/<int:incident_id>"
)
def incident_details(
    incident_id
):
    connection = get_db_connection()

    incident = connection.execute(
        """
        SELECT *
        FROM incidents
        WHERE id = ?
        """,
        (incident_id,)
    ).fetchone()

    if incident is None:
        connection.close()
        abort(404)

    events = connection.execute(
        """
        SELECT *
        FROM events
        WHERE incident_id = ?
        ORDER BY timestamp ASC
        """,
        (incident_id,)
    ).fetchall()

    connection.close()

    attack_progression = []

    for event in events:

        stage = ATTACK_STAGES.get(
            event["event_type"],
            "Unknown"
        )

        if stage not in attack_progression:
            attack_progression.append(
                stage
            )

    # Build MITRE ATT&CK mappings
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


@app.route(
    "/incident/<int:incident_id>/status",
    methods=["POST"]
)
def update_incident_status(
    incident_id
):
    new_status = request.form.get(
        "status",
        ""
    ).strip().upper()

    if new_status not in VALID_STATUSES:
        abort(400)

    connection = get_db_connection()

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

    connection.commit()

    if cursor.rowcount == 0:
        connection.close()
        abort(404)

    connection.close()

    return redirect(
        url_for(
            "incident_details",
            incident_id=incident_id
        )
    )


if __name__ == "__main__":
    app.run(
        debug=True
    )