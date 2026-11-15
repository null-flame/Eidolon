import sqlite3
import os
import json
import time

class EidolonDB:
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS globals (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module TEXT,
                    target TEXT,
                    vulns TEXT,
                    cvss REAL,
                    started_at REAL,
                    closed_at REAL,
                    status TEXT
                )
            """)

    def get_globals(self):
        cursor = self.conn.execute("SELECT key, value FROM globals")
        res = {}
        for row in cursor:
            try: res[row['key']] = json.loads(row['value'])
            except: res[row['key']] = row['value']
        return res

    def set_global(self, key, value):
        val_str = json.dumps(value)
        with self.conn:
            self.conn.execute("INSERT OR REPLACE INTO globals (key, value) VALUES (?, ?)", (key, val_str))

    def add_session(self, module, target, vulns, cvss):
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO sessions (module, target, vulns, cvss, started_at, status) VALUES (?, ?, ?, ?, ?, ?)",
                (module, target, json.dumps(vulns), cvss, time.time(), "active")
            )
            return cur.lastrowid

    def close_session(self, session_id):
        with self.conn:
            self.conn.execute(
                "UPDATE sessions SET closed_at = ?, status = ? WHERE id = ?",
                (time.time(), "closed", session_id)
            )

    def get_sessions(self):
        cursor = self.conn.execute("SELECT * FROM sessions")
        return [dict(row) for row in cursor]
        
    def get_session(self, session_id):
        cursor = self.conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
        row = cursor.fetchone()
        return dict(row) if row else None