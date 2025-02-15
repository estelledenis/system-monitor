import re
import subprocess
import time

# Authentication patterns
AUTH_PATTERNS = {
    "failed": [
        r"Invalid password",
        r"authentication failed",
        r"SecureToken authentication failed",
        r"opendirectoryd: .* Authentication failed",
        r"loginwindow: .* Invalid token login",
        r"AuthorizationRefused",
    ],
    "success": [
        r"authentication succeeded",
        r"authorization succeeded",
        r"session opened",
        r"opendirectoryd: .* authentication succeeded",
        r"loginwindow: Login successful",
        r"User authentication succeeded",
        r"authd: Succeeded",
        r"session opened for user",
        r"successful authentication",
    ],
}

# Ignore noisy logs
NOISE_FILTERS = [
    r"ks_crypt: .* keychain is locked",
    r"TrustedPeersHelp",
    r"corespeechd",
    r"SecError",
]

# Real-time log stream command
LOG_COMMAND_REALTIME = """
log stream --debug --info --style syslog --predicate '
(subsystem == "com.apple.authd") OR
(subsystem == "com.apple.opendirectoryd") OR
(subsystem == "com.apple.Authorization") OR
(subsystem == "com.apple.loginwindow") OR
(subsystem == "com.apple.securityd") OR
(eventMessage contains[c] "authentication succeeded") OR
(eventMessage contains[c] "session opened") OR
(eventMessage contains[c] "authorization succeeded")'
"""

# 24-hour login history search
LOG_COMMAND_24H = """
log show --last 24h --debug --info --predicate '
(eventMessage contains[c] "login") OR
(eventMessage contains[c] "authentication succeeded") OR
(eventMessage contains[c] "authorization succeeded") OR
(eventMessage contains[c] "session opened")'
"""

def search_past_24h():
    """Fetch login attempts from the last 24 hours."""
    print("🔍 Fetching login attempts from the last 24 hours...\n")
    result = subprocess.run(LOG_COMMAND_24H, shell=True, capture_output=True, text=True)
    process_logs(result.stdout.split("\n"))

def process_logs(log_lines):
    """Process log lines and detect login attempts."""
    for line in log_lines:
        if "Filtering the log data" in line:  
            continue  # Ignore log filter messages

        if any(re.search(pattern, line, re.IGNORECASE) for pattern in AUTH_PATTERNS["failed"]):
            if not any(re.search(noise, line, re.IGNORECASE) for noise in NOISE_FILTERS):
                print(f"[❌ ALERT] Failed login: {clean_log_output(line)}")

        elif any(re.search(pattern, line, re.IGNORECASE) for pattern in AUTH_PATTERNS["success"]):
            print(f"[✅ SUCCESS] Successful login: {clean_log_output(line)}")

def clean_log_output(log_line):
    """Extract relevant information from logs."""
    return re.sub(r"\s+", " ", log_line.strip())  # Remove extra spaces

def monitor_logs():
    """Continuously monitor logs in real-time."""
    print("\n🔍 Monitoring login attempts in real-time...\n")

    process = subprocess.Popen(LOG_COMMAND_REALTIME, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    try:
        for line in iter(process.stdout.readline, ''):
            if line:
                process_logs([line.strip()])
    except KeyboardInterrupt:
        print("\n🛑 Stopping monitoring.")
        process.terminate()

if __name__ == "__main__":
    search_past_24h()
    monitor_logs()
