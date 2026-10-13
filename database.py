
import sqlite3
import json
import hashlib
from pathlib import Path

import pandas as pd


DB_PATH = Path(__file__).resolve().parent / "cyber_sentinels.db"


def get_connection():
    """Open a connection to the incident database."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the incident history table if it does not exist."""
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL UNIQUE,
                account TEXT,
                computer TEXT,
                rule TEXT,
                severity TEXT,
                start_time TEXT,
                end_time TEXT,
                event_ids TEXT,
                evidence TEXT,
                recommendation TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_incident_account
            ON incidents(account)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_incident_computer
            ON incidents(computer)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_incident_rule
            ON incidents(rule)
        """)


def make_fingerprint(incident):
    """
    Identify an exact incident so uploading the same
    detected incident again does not create a duplicate.
    """
    event_ids = incident.get("event_ids", [])

    if isinstance(event_ids, str):
        try:
            event_ids = json.loads(event_ids)
        except (json.JSONDecodeError, TypeError):
            event_ids = [event_ids]

    identity = {
        "account": str(incident.get("account", "")),
        "computer": str(incident.get("computer", "")),
        "rule": str(incident.get("rule", "")),
        "start_time": str(incident.get("start_time", "")),
        "end_time": str(incident.get("end_time", "")),
        "event_ids": sorted(str(x) for x in event_ids),
    }

    raw = json.dumps(identity, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def save_incidents(incidents):
    """
    Save newly detected incidents and attach historical
    counts for their account, computer and detection rule.

    Returns the current incidents with history columns.
    """
    incidents = incidents.copy()

    if incidents.empty:
        for column in [
            "previous_account_incidents",
            "previous_computer_incidents",
            "previous_pattern_incidents",
            "is_recurring",
            "already_recorded",
        ]:
            incidents[column] = pd.Series(dtype="object")

        return incidents

    history_columns = [
        "previous_account_incidents",
        "previous_computer_incidents",
        "previous_pattern_incidents",
        "is_recurring",
        "already_recorded",
    ]

    results = []

    with get_connection() as conn:
        for _, row in incidents.iterrows():
            incident = row.to_dict()

            account = str(incident.get("account", ""))
            computer = str(incident.get("computer", ""))
            rule = str(incident.get("rule", ""))
            fingerprint = make_fingerprint(incident)

            # Check whether this exact incident was saved before.
            existing = conn.execute(
                "SELECT id FROM incidents WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()

            # Count historical incidents before inserting this one.
            account_count = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE account = ?",
                (account,),
            ).fetchone()[0]

            computer_count = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE computer = ?",
                (computer,),
            ).fetchone()[0]

            pattern_count = conn.execute(
                """
                SELECT COUNT(*) FROM incidents
                WHERE account = ? AND computer = ? AND rule = ?
                """,
                (account, computer, rule),
            ).fetchone()[0]

            already_recorded = existing is not None

            if not already_recorded:
                event_ids = incident.get("event_ids", [])

                if not isinstance(event_ids, str):
                    event_ids = json.dumps(
                        event_ids, default=str
                    )

                conn.execute(
                    """
                    INSERT INTO incidents (
                        fingerprint, account, computer, rule,
                        severity, start_time, end_time, event_ids,
                        evidence, recommendation
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        fingerprint,
                        account,
                        computer,
                        rule,
                        str(incident.get("severity", "")),
                        str(incident.get("start_time", "")),
                        str(incident.get("end_time", "")),
                        event_ids,
                        str(incident.get("evidence", "")),
                        str(incident.get("recommendation", "")),
                    ),
                )

            incident["previous_account_incidents"] = account_count
            incident["previous_computer_incidents"] = computer_count
            incident["previous_pattern_incidents"] = pattern_count

            # An exact re-upload is not a new incident.
            incident["already_recorded"] = already_recorded

            incident["is_recurring"] = (
                account_count > 0
                or computer_count > 0
                or pattern_count > 0
            )

            results.append(incident)

    return pd.DataFrame(results)


def get_incident_history():
    """Retrieve all incidents stored across previous uploads."""
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT *
            FROM incidents
            ORDER BY created_at DESC, id DESC
        """).fetchall()

    return pd.DataFrame([dict(row) for row in rows])


def get_recurring_accounts():
    """Find accounts associated with multiple stored incidents."""
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT
                account,
                COUNT(*) AS incident_count,
                COUNT(DISTINCT computer) AS computer_count
            FROM incidents
            GROUP BY account
            HAVING COUNT(*) > 1
            ORDER BY incident_count DESC
        """).fetchall()

    return pd.DataFrame([dict(row) for row in rows])


def get_recurring_computers():
    """Find computers associated with multiple stored incidents."""
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT
                computer,
                COUNT(*) AS incident_count,
                COUNT(DISTINCT account) AS account_count
            FROM incidents
            GROUP BY computer
            HAVING COUNT(*) > 1
            ORDER BY incident_count DESC
        """).fetchall()

    return pd.DataFrame([dict(row) for row in rows])


def get_recurring_patterns():
    """Find repeated account, computer and rule combinations."""
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT
                account,
                computer,
                rule,
                COUNT(*) AS incident_count,
                MAX(created_at) AS last_recorded
            FROM incidents
            GROUP BY account, computer, rule
            HAVING COUNT(*) > 1
            ORDER BY incident_count DESC
        """).fetchall()

    return pd.DataFrame([dict(row) for row in rows])
