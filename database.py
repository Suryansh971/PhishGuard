import sqlite3
from datetime import datetime


DATABASE = "phishguard.db"


def init_db():
    connection = sqlite3.connect(DATABASE)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            malicious INTEGER DEFAULT 0,
            suspicious INTEGER DEFAULT 0,
            harmless INTEGER DEFAULT 0,
            undetected INTEGER DEFAULT 0,
            scanned_at TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_scan(url, risk_score, risk_level, vt_stats):
    connection = sqlite3.connect(DATABASE)

    connection.execute("""
        INSERT INTO scans (
            url,
            risk_score,
            risk_level,
            malicious,
            suspicious,
            harmless,
            undetected,
            scanned_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        url,
        risk_score,
        risk_level,
        vt_stats.get("malicious", 0),
        vt_stats.get("suspicious", 0),
        vt_stats.get("harmless", 0),
        vt_stats.get("undetected", 0),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    connection.commit()
    connection.close()


def get_scan_history():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    scans = connection.execute("""
        SELECT *
        FROM scans
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return scans

def get_dashboard_stats():
    connection = sqlite3.connect(DATABASE)

    total_scans = connection.execute(
        "SELECT COUNT(*) FROM scans"
    ).fetchone()[0]

    high_risk = connection.execute(
        "SELECT COUNT(*) FROM scans WHERE risk_level = 'High Risk'"
    ).fetchone()[0]

    medium_risk = connection.execute(
        "SELECT COUNT(*) FROM scans WHERE risk_level = 'Medium Risk'"
    ).fetchone()[0]

    low_risk = connection.execute(
        "SELECT COUNT(*) FROM scans WHERE risk_level = 'Low Risk'"
    ).fetchone()[0]

    malicious = connection.execute(
        "SELECT COALESCE(SUM(malicious), 0) FROM scans"
    ).fetchone()[0]

    connection.close()

    return {
        "total_scans": total_scans,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "low_risk": low_risk,
        "malicious": malicious
    }