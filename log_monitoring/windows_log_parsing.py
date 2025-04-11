import win32evtlog
import win32con
import datetime
import time

def read_windows_login_events(server='localhost', log_type='Security', last_hours=24):
    """
    Reads login-related events from Windows Security log for the last N hours.
    Event ID 4624 = Successful login
    Event ID 4625 = Failed login
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
                msg = f"🕒 {event.TimeGenerated.Format()} | {'✅ SUCCESS' if event.EventID == 4624 else '❌ ALERT'} | User: {user} | Source: {process}"
                events.append(msg)
    return list(reversed(events))

def monitor_log_realtime(poll_interval=5):
    """ Continuously monitor and print new login events every N seconds """
    seen = set()
    while True:
        new_events = read_windows_login_events()
        for event in new_events:
            if event not in seen:
                print(event)
                seen.add(event)
        time.sleep(poll_interval)

if __name__ == '__main__':
    print("🔍 Real-time Windows login monitoring started...")
    monitor_log_realtime(poll_interval=5)
