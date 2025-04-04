import re
import time
import subprocess
import sys  # Import sys for stdout flushing

# Define regex patterns to detect failed and successful logins
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
    r"Touch ID was used",
    r"user authenticated",
    r"biometric authentication succeeded",
    r"authenticated using biometrics"
]

# Ignore noisy keychain and system security logs
NOISE_FILTERS = [
    r"ks_crypt: .* keychain is locked",
    r"TrustedPeersHelp",
    r"corespeechd",
    r"SecError",
]

# Expanded log predicates to include biometrics, Touch ID, and authentication events
REAL_TIME_LOG_COMMAND = """log stream --style syslog \
--predicate 'subsystem BEGINSWITH "com.apple." AND (
    composedMessage CONTAINS[c] "authentication" OR
    composedMessage CONTAINS[c] "authorization succeeded" OR
    composedMessage CONTAINS[c] "session opened" OR
    composedMessage CONTAINS[c] "Touch ID" OR
    composedMessage CONTAINS[c] "biometric" OR
    composedMessage CONTAINS[c] "user authenticated"
)' \
--info"""

PAST_24H_LOG_COMMAND = """log show --last 24h \
--predicate 'subsystem BEGINSWITH "com.apple." AND (
    composedMessage CONTAINS[c] "authentication failed" OR
    composedMessage CONTAINS[c] "login failed" OR
    composedMessage CONTAINS[c] "Touch ID" OR
    composedMessage CONTAINS[c] "biometric" OR
    composedMessage CONTAINS[c] "user authenticated"
)' \
--info"""

def search_past_24h():
    """Fetch failed and successful login attempts from the last 24 hours."""
    result = subprocess.run(PAST_24H_LOG_COMMAND, shell=True, capture_output=True, text=True)

    # Ignore the first line which contains the filtering query
    log_lines = result.stdout.split("\n")[1:]
    process_logs(log_lines)

def process_logs(log_lines):
    """Process log lines to detect failed and successful login attempts."""
    for line in log_lines:
        if any(re.search(pattern, line, re.IGNORECASE) for pattern in FAILED_LOGIN_PATTERNS):
            if not any(re.search(noise, line, re.IGNORECASE) for noise in NOISE_FILTERS):
                explanation = generate_explanation(line, "failed")
                print(f"[❌ ALERT] Failed login: {clean_log_output(line)}")
                print(f"ℹ️ {explanation}\n", flush=True)

        elif any(re.search(pattern, line, re.IGNORECASE) for pattern in SUCCESSFUL_LOGIN_PATTERNS):
            explanation = generate_explanation(line, "success")
            print(f"[✅ SUCCESS] Successful login: {clean_log_output(line)}")
            print(f"ℹ️ {explanation}\n", flush=True)

def generate_explanation(log_line, status):
    """Generate a brief explanation for each login attempt."""
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
    elif "touch id" in lower:
        return "User successfully logged in using Touch ID."
    elif "biometric" in lower:
        return "Biometric login (e.g., Touch ID) was used to authenticate."
    elif "user authenticated" in lower:
        return "User successfully authenticated — possibly via biometrics or smartcard."
    elif "opendirectoryd" in lower:
        if status == "failed":
            return "Authentication failed at the directory service level."
        else:
            return "Authentication succeeded at the directory service level."
    return "Unknown login event detected."

def clean_log_output(log_line):
    """Extract relevant information from log lines to keep output concise."""
    return re.sub(r"\s+", " ", log_line.strip())

def monitor_logs():
    """Continuously monitor logs in real-time."""
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

