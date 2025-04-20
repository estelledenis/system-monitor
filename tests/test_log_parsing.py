from log_monitoring import log_parsing

def test_parse_logs_empty():
    logs = []
    parsed = log_parsing.parse_logs(logs)
    assert parsed == []

def test_parse_logs_invalid():
    logs = [{}]
    parsed = log_parsing.parse_logs(logs)
    assert isinstance(parsed, list)
    assert parsed[0]["event_id"] == 0
    assert parsed[0]["message"] == ""

def test_parse_logs_valid():
    logs = [{"event_id": 1, "message": "Test Event"}]
    parsed = log_parsing.parse_logs(logs)
    assert isinstance(parsed, list)
    assert parsed[0]["event_id"] == 1
    assert parsed[0]["message"] == "Test Event"
