from tests import setup_test_environment
setup_test_environment()

from log_monitoring import windows_log_parsing as logs

def test_read_windows_login_events_returns_list():
    events = logs.read_windows_login_events(last_hours=1)
    assert isinstance(events, list)
