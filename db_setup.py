import sqlite3
import os

def create_tables(db_path="system_monitor.db"):
    """
    Creates the necessary tables if they do not exist.
    """
    # Create DB file in the same directory, if not existing
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Example table for login attempts
    c.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT,
            status TEXT NOT NULL,
            event_time TEXT
        );
    ''')

    conn.commit()
    conn.close()
    print(f"Database tables ensured at {os.path.abspath(db_path)}")

