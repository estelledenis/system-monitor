import re
import time
import subprocess
import sys
from datetime import datetime, timedelta

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

NOISE_FILTERS = [
    r"ks_crypt: .* keychain is locked",
    r"TrustedPeersHelp",
    r"corespeechd",
    r"SecError",
]

REAL_TIME_LOG_COMMAND = """log stream --style syslog \
--predicate 'subsystem BEGINSWITH "com.apple." AND (
    composedMessage CONTAINS[c] "authentication" OR
    composedMessage CONTAINS[c] "authorization succeeded" OR
    composedMessage CONTAINS[c] "session opened" OR
    composedMessage CONTAINS[c] "Touch ID or Enter Password" OR
    composedMessage CONTAINS[c] "user authenticated"
)' \
--info"""

PAST_24H_LOG_COMMAND = """log show --last 24h \
--predicate 'subsystem BEGINSWITH "com.apple." AND (
    composedMessage CONTAINS[c] "authentication failed" OR
    composedMessage CONTAINS[c] "login failed" OR
    composedMessage CONTAINS[c] "Touch ID or Enter Password"
)' \
--info"""

touch_id_prompt_time = None
last_touch_prompt_time = None
touch_id_window = timedelta(seconds=10)

def search_past_24h():
    result = subprocess.run(PAST_24H_LOG_COMMAND, shell=True, capture_output=True, text=True)
    log_lines = result.stdout.split("\n")[1:]
    process_logs(log_lines)

def process_logs(log_lines):
    global touch_id_prompt_time, last_touch_prompt_time

    for line in log_lines:
        if not line.strip():
            continue

        timestamp = extract_timestamp(line)
        ts_str = timestamp.strftime("[%Y-%m-%d %H:%M:%S]") if timestamp else "[?]"
        log_summary = summarize_log(line)

        # Deduplicate Touch ID prompts within 2 seconds
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

        elif any(re.search(pat, line, re.IGNORECASE) for pat in FAILED_LOGIN_PATTERNS):
            if not any(re.search(noise, line, re.IGNORECASE) for noise in NOISE_FILTERS):
                explanation = generate_explanation(line, "failed")
                print("\n" + "━" * 40)
                print(f"[❌ ALERT] Login Failed")
                print(f"🕒 {ts_str}")
                print(f"🔍 {log_summary}")
                print(f"ℹ️ {explanation}")
                print("━" * 40, flush=True)

        elif any(re.search(pat, line, re.IGNORECASE) for pat in SUCCESSFUL_LOGIN_PATTERNS):
            if touch_id_prompt_time and timestamp and timestamp - touch_id_prompt_time <= touch_id_window:
                print("\n" + "━" * 40)
                print(f"[✅ TOUCH ID] Login Successful (inferred via Touch ID)")
                print(f"🕒 {ts_str}")
                print(f"🔍 {log_summary}")
                print("━" * 40, flush=True)
                touch_id_prompt_time = None
            else:
                explanation = generate_explanation(line, "success")
                print("\n" + "━" * 40)
                print(f"[✅ SUCCESS] Login Accepted")
                print(f"🕒 {ts_str}")
                print(f"🔍 {log_summary}")
                print(f"ℹ️ {explanation}")
                print("━" * 40, flush=True)

def extract_timestamp(log_line):
    try:
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
        return "Authentication succeeded at the directory service level." if status == "success" else "Authentication failed at the directory service level."
    return "Unknown login event detected."

def summarize_log(log_line):
    # Clean line and remove unnecessary parts like spinner
    line = clean_log_output(log_line)
    line = re.sub(r",?\s*spinner:\d+", "", line, flags=re.IGNORECASE)

    for keyword in ["Authentication", "authorization", "Touch ID", "session", "loginwindow", "opendirectoryd"]:
        if keyword in line:
            idx = line.find(keyword)
            return line[idx:]

    return line

def clean_log_output(log_line):
    return re.sub(r"\s+", " ", log_line.strip())

def monitor_logs():
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
