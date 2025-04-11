import win32evtlog
import win32con
import datetime

def read_windows_login_events(server='localhost', log_type='Security', max_events=100):
    """
    Reads login-related events from Windows Security log.
    Event ID 4624 = Successful login
    Event ID 4625 = Failed login
    """
    events = []
    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    total = 0
    while total < max_events:
        records = win32evtlog.ReadEventLog(hand, flags, 0)
        if not records:
            break
        for event in records:
            if event.EventID in [4624, 4625]:
                entry = {
                    "timestamp": event.TimeGenerated.Format(),
                    "event_id": event.EventID,
                    "success": event.EventID == 4624,
                    "source": event.SourceName,
                    "description": event.StringInserts
                }
                events.append(entry)
                total += 1
                if total >= max_events:
                    break
    return events

if __name__ == '__main__':
    for e in read_windows_login_events():
        print(e)

