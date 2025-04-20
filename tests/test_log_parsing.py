from log_monitoring import log_parsing
import pytest
from log_monitoring import log_parsing
from datetime import datetime, timezone
from unittest.mock import patch

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

def test_clean_log_output():
    messy = "    Authentication     succeeded   "
    cleaned = log_parsing.clean_log_output(messy)
    assert cleaned == "Authentication succeeded"

def test_summarize_log_with_keyword():
    log = "2025-04-19 22:00:00 authentication succeeded user"
    summary = log_parsing.summarize_log(log)
    assert "authentication succeeded" in summary

def test_summarize_log_without_keyword():
    log = "2025-04-19 22:00:00 unrelated log entry"
    summary = log_parsing.summarize_log(log)
    assert "unrelated log entry" in summary

def test_generate_explanation_known_failure():
    line = "Authentication failed"
    explanation = log_parsing.generate_explanation(line, status="failed")
    assert "incorrect" in explanation.lower()

def test_generate_explanation_known_success():
    line = "Authorization succeeded"
    explanation = log_parsing.generate_explanation(line, status="success")
    assert "granted access" in explanation.lower()

def test_generate_explanation_unknown():
    line = "Some weird unknown event"
    explanation = log_parsing.generate_explanation(line, status="failed")
    assert "unknown login" in explanation.lower()

def test_extract_timestamp_valid():
    line = "2025-04-19 22:00:00.123456+0000 Authentication succeeded"
    timestamp = log_parsing.extract_timestamp(line)
    assert isinstance(timestamp, datetime)
    assert timestamp.tzinfo is not None

def test_extract_timestamp_invalid():
    line = "invalid timestamp line"
    timestamp = log_parsing.extract_timestamp(line)
    assert timestamp is None

@patch("builtins.print")
def test_process_logs_ssh(mock_print):
    ssh_log = "2025-04-19 22:00:00.123456+0000 sshd Accepted password for user1 from 192.168.1.10"
    log_parsing.process_logs([ssh_log])
    printed_text = "".join(str(call.args) for call in mock_print.call_args_list)
    assert "Remote login" in printed_text

@patch("builtins.print")
def test_process_logs_failed_login(mock_print):
    fail_log = "2025-04-19 22:00:00.123456+0000 Authentication failed"
    log_parsing.process_logs([fail_log])
    printed_text = "".join(str(call.args) for call in mock_print.call_args_list)
    assert "Login Failed" in printed_text

@patch("builtins.print")
def test_process_logs_success_login(mock_print):
    success_log = "2025-04-19 22:00:00.123456+0000 Authorization succeeded"
    log_parsing.process_logs([success_log])
    printed_text = "".join(str(call.args) for call in mock_print.call_args_list)
    assert "Login Accepted" in printed_text

