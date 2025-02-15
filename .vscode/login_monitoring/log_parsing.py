import re
import time

# Path to CUPS access log file (default location)
LOG_FILE_PATH = "/var/log/cups/access_log"

# Patterns for authentication events
SUCCESS_PATTERN = re.compile(r'(\S+) - (\S+) \[(.*?)\] "POST .*" 200')
FAILURE_PATTERN = re.compile(r'(\S+) - (-|\S+) \[(.*?)\] "POST .*" 401')

def tail_log(file_path):
    """Dynamically read new lines from the log file."""
    with open(file_path, "r") as log_file:
        log_file.seek(0, 2)  # Move to the end of the file
        while True:
            line = log_file.readline()
            if not line:
                time.sleep(1)  # Wait for new log entries
                continue
            process_log_line(line.strip())

def process_log_line(line):
    """Process a single log line and classify authentication attempts."""
    success_match = SUCCESS_PATTERN.search(line)
    failure_match = FAILURE_PATTERN.search(line)

    if success_match:
        ip, user, timestamp = success_match.groups()
        print(f"[✅ SUCCESS] User '{user}' logged in from {ip} at {timestamp}")

    elif failure_match:
        ip, user, timestamp = failure_match.groups()
        user_display = user if user != "-" else "Unknown"
        print(f"[❌ FAILED] Failed login from {ip} at {timestamp} (User: {user_display})")

if __name__ == "__main__":
    print("🔍 Monitoring CUPS authentication logs in real-time...\n")
    tail_log(LOG_FILE_PATH)
