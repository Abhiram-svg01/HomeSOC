import sqlite3
from pathlib import Path

from correlation_engine import calculate_incident_severity


DB_PATH = Path("data/homesoc.db")


def get_connection():
    DB_PATH.parent.mkdir(exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def init_database():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_ip TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            total_score INTEGER NOT NULL,
            severity TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'NEW'
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            asset_ip TEXT,
            description TEXT,
            FOREIGN KEY (incident_id)
                REFERENCES incidents(id)
        )
        """
    )

    # Upgrade older HomeSOC databases automatically
    cursor.execute("PRAGMA table_info(incidents)")
    columns = {
        row["name"]
        for row in cursor.fetchall()
    }

    if "status" not in columns:
        cursor.execute(
            """
            ALTER TABLE incidents
            ADD COLUMN status TEXT NOT NULL DEFAULT 'NEW'
            """
        )

    connection.commit()
    connection.close()


def save_incident(incident):
    connection = get_connection()
    cursor = connection.cursor()

    existing = cursor.execute(
        """
        SELECT id
        FROM incidents
        WHERE asset_ip = ?
          AND start_time = ?
          AND end_time = ?
          AND total_score = ?
          AND event_count = ?
        """,
        (
            incident["asset_ip"],
            incident["start_time"],
            incident["end_time"],
            incident["total_score"],
            len(incident["events"])
        )
    ).fetchone()

    if existing:
        connection.close()
        return existing["id"]

    severity = calculate_incident_severity(
        incident["total_score"]
    )

    cursor.execute(
        """
        INSERT INTO incidents (
            asset_ip,
            start_time,
            end_time,
            total_score,
            severity,
            event_count,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            incident["asset_ip"],
            incident["start_time"],
            incident["end_time"],
            incident["total_score"],
            severity,
            len(incident["events"]),
            "NEW"
        )
    )

    incident_id = cursor.lastrowid

    for event in incident["events"]:
        cursor.execute(
            """
            INSERT INTO events (
                incident_id,
                timestamp,
                source,
                event_type,
                severity,
                risk_score,
                src_ip,
                dst_ip,
                asset_ip,
                description
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                event["timestamp"],
                event["source"],
                event["event_type"],
                event["severity"],
                event["risk_score"],
                event["src_ip"],
                event["dst_ip"],
                event["asset_ip"],
                event["description"]
            )
        )

    connection.commit()
    connection.close()

    return incident_id