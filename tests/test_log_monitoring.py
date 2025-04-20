import pytest
from log_monitoring import windows_log_parsing as logs

def test_parse_login_events(monkeypatch):
    class DummyEvent:
        def __init__(self, event_id, username, process):
            self.EventID = event_id
            self.TimeGenerated = logs.datetime.datetime.now()
            self.RecordNumber = 12345
            self.StringInserts = [""]*6 + [username] + [""]*11 + [process]

    def dummy_read_event_log(*args, **kwargs):
        return [DummyEvent(4624, "TestUser", "127.0.0.1")]

    monkeypatch.setattr(logs.win32evtlog, "ReadEventLog", dummy_read_event_log)
    monkeypatch.setattr(logs.win32evtlog, "OpenEventLog", lambda server, log: None)

    events = logs.read_windows_login_events(last_hours=1)
    assert any("SUCCESS" in e for e in events)
