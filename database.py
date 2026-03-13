# ============================================
# Adaptive Cyber Resilience and Automated
# Threat Neutralization System (ACRTS)
# Team  : Jahnavi Singh, Darsh Bindra,
#          Aayushi Malik, Mohini
# Repo  : https://github.com/jahnavi-37
# Version: 1.0
# ============================================

import sqlite3
from typing import List, Dict, Union

import config


SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    log_source TEXT,
    threat_type TEXT,
    ip_address TEXT,
    severity TEXT,
    risk_score INTEGER,
    mitre_technique_id TEXT,
    mitre_technique_name TEXT,
    mitre_tactic TEXT,
    action_taken TEXT,
    status TEXT
);
"""


def init_db() -> None:
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.execute(SCHEMA)
        conn.commit()


def save_incident(incident: Dict[str, Union[str, int]]) -> None:
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO incidents (
                timestamp, log_source, threat_type, ip_address, severity,
                risk_score, mitre_technique_id, mitre_technique_name,
                mitre_tactic, action_taken, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident.get("timestamp"),
                incident.get("log_source"),
                incident.get("threat_type"),
                incident.get("ip_address"),
                incident.get("severity"),
                incident.get("risk_score"),
                incident.get("mitre_technique_id"),
                incident.get("mitre_technique_name"),
                incident.get("mitre_tactic"),
                incident.get("action_taken"),
                incident.get("status", "DETECTED"),
            ),
        )
        conn.commit()


def get_all_incidents() -> List[Dict[str, Union[str, int]]]:
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM incidents ORDER BY id DESC").fetchall()
        return [dict(row) for row in rows]


def get_incidents_by_severity(severity: str) -> List[Dict[str, Union[str, int]]]:
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM incidents WHERE severity = ? ORDER BY id DESC",
            (severity,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_top_ips(limit: int = 5) -> List[Dict[str, Union[str, int]]]:
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT ip_address, COUNT(*) as count
            FROM incidents
            GROUP BY ip_address
            ORDER BY count DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_threat_counts() -> List[Dict[str, Union[str, int]]]:
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT threat_type, COUNT(*) as count
            FROM incidents
            GROUP BY threat_type
            ORDER BY count DESC
            """
        ).fetchall()
        return [dict(row) for row in rows]
