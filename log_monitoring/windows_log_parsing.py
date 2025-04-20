import win32evtlog
import win32con
import datetime
import time
import sys
import io
import os

try:
    from db_operations import insert_login_attempt
except ImportError:
    def insert_login_attempt(*args, **kwargs):
        pass

def read_windows_login_events(server='localhost', log_type='Security', last_hours=24):
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
            if event.TimeGenerated < time_cutoff:
                return list(reversed(events))

            if event.EventID in [4624, 4625]:
                key = (event.RecordNumber, event.TimeGenerated)
                if key in seen:
                    continue
                seen.add(key)

                inserts = event.StringInserts or []
                user = inserts[5] if len(inserts) > 5 else "?"
                process = inserts[17] if len(inserts) > 17 else "?"
                status = "SUCCESS" if event.EventID == 4624 else "FAILURE"
                event_time_str = event.TimeGenerated.Format()

                msg = f"[{event_time_str}] | {status} | User: {user} | Source: {process}"
                events.append(msg)

                insert_login_attempt(
                    username=user,
                    ip_address=process,
                    status=status,
                    event_time=event_time_str
                )

    return list(reversed(events))

def monitor_log_realtime(poll_interval=5):
    seen = set()
    while True:
        new_events = read_windows_login_events()
        for event in new_events:
            if event not in seen:
                print(event)
                seen.add(event)
        time.sleep(poll_interval)

if __name__ == '__main__':
    # 💥 Move sys.stdout fixing INSIDE __main__ so it does NOT affect pytest
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    os.system("chcp 65001 >nul")

    print("Real-time Windows login monitoring started...", flush=True)
    monitor_log_realtime(poll_interval=5)
