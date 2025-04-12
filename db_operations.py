import sqlite3

def insert_login_attempt(username, ip_address, status, event_time=None, db_path="system_monitor.db"):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip_address TEXT,
            status TEXT NOT NULL,
            event_time TEXT
        )
    ''')
    c.execute('''
        INSERT INTO login_attempts (username, ip_address, status, event_time)
        VALUES (?, ?, ?, ?)
    ''', (username, ip_address, status, event_time))
    conn.commit()
    conn.close()

def get_recent_logins(limit=50, db_path="system_monitor.db"):
    """
    Retrieves the most recent login attempts, defaulting to 50 records.
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
        SELECT username, ip_address, status, timestamp
        FROM login_attempts
        ORDER BY id DESC
        LIMIT ?
    ''', (limit,))
    rows = c.fetchall()
    conn.close()
    return rows
