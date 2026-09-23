import sqlite3
from pathlib import Path

from flask import Flask, render_template, abort


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates")
)

DB_PATH = PROJECT_ROOT / "data" / "homesoc.db"


def get_db_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


@app.route("/")
def dashboard():
    connection = get_db_connection()

    incidents = connection.execute(
        """
        SELECT *
        FROM incidents
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return render_template(
        "dashboard.html",
        incidents=incidents
    )


@app.route("/incident/<int:incident_id>")
def incident_details(incident_id):
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

    return render_template(
        "incident.html",
        incident=incident,
        events=events
    )


if __name__ == "__main__":
    app.run(debug=True)