import win32evtlog
import win32con
import datetime
import time
import sys
import io
import os

# 1. IMPORT YOUR DB FUNCTION
# Make sure you have a db_operations.py with insert_login_attempt defined as described above.
try:
    from db_operations import insert_login_attempt
except ImportError:
    def insert_login_attempt(*args, **kwargs):
        # Fallback if db_operations isn't available
        pass

# Setup Python to handle UTF-8 output on Windows terminals
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
os.system("chcp 65001")


def read_windows_login_events(server='localhost', log_type='Security', last_hours=24):
    """
    Reads Windows security event logs from the last `last_hours` hours.
    EventIDs of interest:
      - 4624 = An account was successfully logged on.
      - 4625 = An account failed to log on.

    Returns a list of strings describing each event.
    Also calls insert_login_attempt(...) for each new record.
    """
    events = []
    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    time_cutoff = datetime.datetime.now() - datetime.timedelta(hours=last_hours)
    seen = set()

    while True:
        records = win32evtlog.ReadEventLog(hand, flags, 0)
        if not records:
            break
        for event in records:
            # If the event is older than our cutoff, stop reading
            if event.TimeGenerated < time_cutoff:
                return list(reversed(events))

            # We only care about 4624 (success) or 4625 (failure)
            if event.EventID in [4624, 4625]:
                # Use (RecordNumber, TimeGenerated) to deduplicate
                key = (event.RecordNumber, event.TimeGenerated)
                if key in seen:
                    continue
                seen.add(key)

                # Extract relevant fields from StringInserts
                inserts = event.StringInserts or []
                # Typically for ID 4624/4625, inserts[5] = username, inserts[17] = source IP or domain
                user = inserts[5] if len(inserts) > 5 else "?"
                process = inserts[17] if len(inserts) > 17 else "?"
                status = "SUCCESS" if event.EventID == 4624 else "FAILURE"

                # Convert time generated to a string (e.g. "2025-04-15 10:12:05")
                # event.TimeGenerated is a pywintypes.datetime
                event_time_str = event.TimeGenerated.Format()

                msg = f"[{event_time_str}] | {status} | User: {user} | Source: {process}"
                events.append(msg)

                # 2. INSERT INTO THE DATABASE
                # Adjust columns for your schema: 
                insert_login_attempt(
                    username=user,
                    ip_address=process,   # or rename to something else if it's not truly an IP
                    status=status,
                    event_time=event_time_str
                )

    return list(reversed(events))


def monitor_log_realtime(poll_interval=5):
    """
    Continuously reads new Windows Security log events every `poll_interval` seconds
    and prints them to stdout. Each new event is also inserted into the DB inside
    read_windows_login_events().
    """
    seen = set()

    while True:
        # read_windows_login_events will handle DB insertion for anything new
        new_events = read_windows_login_events()
        for event in new_events:
            if event not in seen:
                print(event)
                seen.add(event)
        time.sleep(poll_interval)


if __name__ == '__main__':
    print("Real-time Windows login monitoring started...", flush=True)
    # This will poll the logs every 5 seconds, print new events, and insert them into the DB
    monitor_log_realtime(poll_interval=5)
