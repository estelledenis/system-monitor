import sqlite3

def insert_login_attempt(username, ip_address, status, db_path="system_monitor.db"):
    """
    Inserts a new login attempt record into the 'login_attempts' table.
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
        INSERT INTO login_attempts (username, ip_address, status)
        VALUES (?, ?, ?)
    ''', (username, ip_address, status))
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
