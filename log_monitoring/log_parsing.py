import re
import time
import subprocess
import sys
from datetime import datetime, timedelta

# 1. IMPORT YOUR DB FUNCTION
# Make sure you have db_operations.py with insert_login_attempt defined.
# Example:
# def insert_login_attempt(username, ip_address, status, event_time=None, db_path="system_monitor.db"):
#     ...
from db_operations import insert_login_attempt


# Patterns
FAILED_LOGIN_PATTERNS = [
    r"Invalid password",
    r"authentication failed",
    r"SecureToken authentication failed",
    r"opendirectoryd: .* Authentication failed",
    r"loginwindow: .* Invalid token login",
]

SUCCESSFUL_LOGIN_PATTERNS = [
    r"Authentication succeeded",
    r"authorization succeeded",
    r"session opened",
    r"opendirectoryd: .* Authentication succeeded",
]

TOUCH_ID_PROMPT_PATTERN = r"Touch ID or Enter Password"
SSH_LOGIN_PATTERN = r"sshd.*Accepted.*for (\w+) from ([\d\.]+)"

NOISE_FILTERS = [
    r"ks_crypt: .* keychain is locked",
    r"TrustedPeersHelp",
    r"corespeechd",
    r"SecError",
]

# Log commands (macOS example)
REAL_TIME_LOG_COMMAND = """log stream --style syslog \
--predicate '(process == "sshd" OR composedMessage CONTAINS[c] "authentication" OR composedMessage CONTAINS[c] "authorization succeeded" OR composedMessage CONTAINS[c] "session opened" OR composedMessage CONTAINS[c] "Touch ID or Enter Password" OR composedMessage CONTAINS[c] "user authenticated")' \
--info"""

PAST_24H_LOG_COMMAND = """log show --last 24h \
--predicate '(process == "sshd" OR composedMessage CONTAINS[c] "authentication failed" OR composedMessage CONTAINS[c] "login failed" OR composedMessage CONTAINS[c] "Touch ID or Enter Password")' \
--info"""

# Timers and duplicate filters
touch_id_prompt_time = None
last_touch_prompt_time = None
last_failed_log = ""
last_failed_time = None
touch_id_window = timedelta(seconds=10)

def search_past_24h():
    """
    Runs the log command for the past 24 hours and processes each line.
    """
    result = subprocess.run(PAST_24H_LOG_COMMAND, shell=True, capture_output=True, text=True)
    log_lines = result.stdout.split("\n")[1:]
    process_logs(log_lines)

def process_logs(log_lines):
    """
    Core logic to detect different login events, print them, and store them to the DB.
    """
    global touch_id_prompt_time, last_touch_prompt_time, last_failed_log, last_failed_time

    for line in log_lines:
        if not line.strip():
            continue

        timestamp = extract_timestamp(line)
        ts_str = timestamp.strftime("[%Y-%m-%d %H:%M:%S]") if timestamp else "[?]"
        log_summary = summarize_log(line)

        # 2. DEFAULTS FOR DB STORAGE
        event_time = timestamp.strftime("%Y-%m-%d %H:%M:%S") if timestamp else None
        username = "Unknown"
        ip_address = "Unknown"
        status = "INFO"  # We'll override as SUCCESS/FAILURE/SSH_LOGIN, etc.

        # SSH login detection
        ssh_match = re.search(SSH_LOGIN_PATTERN, line)
        if ssh_match:
            username, ip_address = ssh_match.groups()
            status = "SSH_LOGIN"

            print("\n" + "━" * 40)
            print(f"[🌐 SSH LOGIN] Remote login detected")
            print(f"🕒 {ts_str}")
            print(f"👤 User: {username}")
            print(f"📍 IP: {ip_address}")
            print("━" * 40, flush=True)

            # 3. STORE EVENT IN DB
            insert_login_attempt(username, ip_address, status, event_time)
            continue

        # Touch ID Prompt deduplication
        if TOUCH_ID_PROMPT_PATTERN in line:
            if last_touch_prompt_time and timestamp and (timestamp - last_touch_prompt_time).total_seconds() < 2:
                continue
            last_touch_prompt_time = timestamp
            touch_id_prompt_time = timestamp

            print("\n" + "━" * 40)
            print(f"[🟡 INFO] Touch ID Prompt Detected")
            print(f"🕒 {ts_str}")
            print(f"🔍 {log_summary}")
            print("━" * 40, flush=True)
            # This might be purely informational, so we won't store or we can store "TOUCH_ID_PROMPT"
            # insert_login_attempt("Unknown", "Unknown", "TOUCH_ID_PROMPT", event_time)

        # Failed Login
        elif any(re.search(pat, line, re.IGNORECASE) for pat in FAILED_LOGIN_PATTERNS):
            if not any(re.search(noise, line, re.IGNORECASE) for noise in NOISE_FILTERS):
                # deduplicate repeated lines
                if (
                    last_failed_log == line
                    and last_failed_time
                    and timestamp
                    and (timestamp - last_failed_time).total_seconds() < 2
                ):
                    continue  # Suppress duplicate
                last_failed_log = line
                last_failed_time = timestamp

                status = "FAILURE"
                explanation = generate_explanation(line, "failed")

                # If Touch ID was recently prompted, note it
                if (
                    "opendirectoryd" in line.lower()
                    and touch_id_prompt_time
                    and timestamp
                    and (timestamp - touch_id_prompt_time) < touch_id_window
                ):
                    explanation += " (This may be a background system retry after Touch ID.)"

                print("\n" + "━" * 40)
                print(f"[❌ ALERT] Login Failed")
                print(f"🕒 {ts_str}")
                print(f"🔍 {log_summary}")
                print(f"ℹ️ {explanation}")
                print("━" * 40, flush=True)

                # 3. STORE EVENT IN DB
                insert_login_attempt(username, ip_address, status, event_time)

        # Successful Login
        elif any(re.search(pat, line, re.IGNORECASE) for pat in SUCCESSFUL_LOGIN_PATTERNS):
            if touch_id_prompt_time and timestamp and timestamp - touch_id_prompt_time <= touch_id_window:
                status = "SUCCESS (TouchID)"
                print("\n" + "━" * 40)
                print(f"[✅ TOUCH ID] Login Successful (inferred via Touch ID)")
                print(f"🕒 {ts_str}")
                print(f"🔍 {log_summary}")
                print("━" * 40, flush=True)

                # Clear the last prompt time
                touch_id_prompt_time = None

                # 3. STORE EVENT IN DB
                insert_login_attempt(username, ip_address, status, event_time)
            else:
                status = "SUCCESS"
                explanation = generate_explanation(line, "success")
                print("\n" + "━" * 40)
                print(f"[✅ SUCCESS] Login Accepted")
                print(f"🕒 {ts_str}")
                print(f"🔍 {log_summary}")
                print(f"ℹ️ {explanation}")
                print("━" * 40, flush=True)

                # 3. STORE EVENT IN DB
                insert_login_attempt(username, ip_address, status, event_time)

def extract_timestamp(log_line):
    """
    Attempts to parse the log line's first two fields as a datetime with timezone.
    Example: 2025-04-11 09:35:33.123456-0700
    Adjust this if your logs differ in format.
    """
    try:
        # log_line starts with "2025-04-11 09:35:33.123456-0700"
        ts_str = log_line.split()[0] + " " + log_line.split()[1]
        return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f%z")
    except Exception:
        return None

def generate_explanation(log_line, status):
    lower = log_line.lower()
    if "authentication failed" in lower:
        return "An authentication attempt was made, but the credentials were incorrect."
    elif "invalid password" in lower:
        return "A user attempted to log in but entered the wrong password."
    elif "securetoken authentication failed" in lower:
        return "A system-level authentication attempt using SecureToken was unsuccessful."
    elif "session opened" in lower:
        return "A new login session was successfully established."
    elif "authorization succeeded" in lower:
        return "A user successfully authenticated and was granted access."
    elif "opendirectoryd" in lower:
        return ("Authentication succeeded at the directory service level."
                if status == "success"
                else "Authentication failed at the directory service level.")
    return "Unknown login event detected."

def summarize_log(log_line):
    """
    Extracts a shorter summary portion of the log line for printing.
    """
    line = clean_log_output(log_line)
    line = re.sub(r",?\s*spinner:\d+", "", line, flags=re.IGNORECASE)

    # Return text starting from a known keyword
    for keyword in ["Authentication", "authorization", "Touch ID", "session", "loginwindow", "opendirectoryd"]:
        if keyword in line:
            idx = line.find(keyword)
            return line[idx:]
    return line

def clean_log_output(log_line):
    """
    Removes extra whitespace, newlines, etc., for a cleaner summary.
    """
    return re.sub(r"\s+", " ", log_line.strip())

def monitor_logs():
    """
    Continuously reads new log events in real time (macOS example) and processes them.
    Stop with Ctrl+C.
    """
    process = subprocess.Popen(
        REAL_TIME_LOG_COMMAND, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    print("🔍 Monitoring login attempts in real-time...\n", flush=True)

    try:
        for line in iter(process.stdout.readline, ''):
            if "Filtering the log data" in line:
                continue
            process_logs([line.strip()])
    except KeyboardInterrupt:
        print("\n🛑 Stopping monitoring.", flush=True)
        process.terminate()

if __name__ == "__main__":
    print("🔍 Fetching login attempts from the last 24 hours...\n", flush=True)
    search_past_24h()
    monitor_logs()
