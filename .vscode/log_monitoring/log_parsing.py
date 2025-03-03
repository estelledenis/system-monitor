import re
import time
import subprocess

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
]

# Ignore noisy keychain and system security logs
NOISE_FILTERS = [
    r"ks_crypt: .* keychain is locked",
    r"TrustedPeersHelp",
    r"corespeechd",
    r"SecError",
]

# Log command for real-time monitoring
REAL_TIME_LOG_COMMAND = """log stream --style syslog \
    --predicate 'subsystem == "com.apple.authd" OR subsystem == "com.apple.opendirectoryd" \
    OR subsystem == "com.apple.Authorization" OR subsystem == "com.apple.loginwindow" \
    OR subsystem == "com.apple.securityd" OR composedMessage CONTAINS[c] "authentication" \
    OR composedMessage CONTAINS[c] "session opened" OR composedMessage CONTAINS[c] "authorization succeeded" \
    OR composedMessage CONTAINS[c] "login"' \
    --info"""

# Log command for past 24 hours
PAST_24H_LOG_COMMAND = """log show --last 24h \
    --predicate 'subsystem == "com.apple.authd" OR subsystem == "com.apple.opendirectoryd" \
    OR composedMessage CONTAINS[c] "authentication failed" OR composedMessage CONTAINS[c] "login failed"'"""

def search_past_24h():
    """Fetch failed and successful login attempts from the last 24 hours."""
    result = subprocess.run(PAST_24H_LOG_COMMAND, shell=True, capture_output=True, text=True)
    
    # Ignore the first line which contains the filtering query
    log_lines = result.stdout.split("\n")[1:]  # Skip the first line
    process_logs(log_lines)

def process_logs(log_lines):
    """Process log lines to detect failed and successful login attempts."""
    for line in log_lines:
        if any(re.search(pattern, line, re.IGNORECASE) for pattern in FAILED_LOGIN_PATTERNS):
            if not any(re.search(noise, line, re.IGNORECASE) for noise in NOISE_FILTERS):
                print(f"[❌ ALERT] Failed login: {clean_log_output(line)}")

        elif any(re.search(pattern, line, re.IGNORECASE) for pattern in SUCCESSFUL_LOGIN_PATTERNS):
            print(f"[✅ SUCCESS] Successful login: {clean_log_output(line)}")

def clean_log_output(log_line):
    """Extract relevant information from log lines to keep output concise."""
    return re.sub(r"\s+", " ", log_line.strip())  # Remove extra spaces

def monitor_logs():
    """Continuously monitor logs in real-time."""
    process = subprocess.Popen(REAL_TIME_LOG_COMMAND, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    print("🔍 Monitoring login attempts in real-time...\n")
    
    try:
        for line in iter(process.stdout.readline, ''):
            if "Filtering the log data" in line:  # Ignore log query statement
                continue  
            process_logs([line.strip()])
    except KeyboardInterrupt:
        print("\n🛑 Stopping monitoring.")
        process.terminate()

if __name__ == "__main__":
    print("🔍 Fetching login attempts from the last 24 hours...\n")
    search_past_24h()
    monitor_logs()
