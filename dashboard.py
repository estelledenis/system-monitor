import tkinter as tk
from tkinter import scrolledtext, ttk
import subprocess
import threading
import os
import time
import platform
import tempfile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_PATH = os.path.join(BASE_DIR, "venv")
PYTHON_EXEC = os.path.join(
    VENV_PATH,
    "Scripts" if platform.system() == "Windows" else "bin",
    "python.exe" if platform.system() == "Windows" else "python"
)

if not os.path.exists(PYTHON_EXEC):
    raise FileNotFoundError(f"Python executable not found at {PYTHON_EXEC}")

IS_WINDOWS = platform.system() == "Windows"
progress_bar_running = False
progress_thread = None

root = tk.Tk()
root.title("System Monitoring Dashboard")
root.geometry("750x540")
root.configure(bg="#2C3E50")

output_text = scrolledtext.ScrolledText(root, width=75, height=15, wrap=tk.WORD, bg="#ECF0F1", fg="#2C3E50", font=("Arial", 10))
output_text.pack(pady=10, padx=10)

output_text.tag_config("timestamp", foreground="#2980B9", font=("Arial", 10, "bold"))
output_text.tag_config("success", foreground="#27AE60", font=("Arial", 10, "bold"))
output_text.tag_config("alert", foreground="#C0392B", font=("Arial", 10, "bold"))
output_text.tag_config("touchid", foreground="#9B59B6", font=("Arial", 10, "bold"))
output_text.tag_config("explanation", foreground="#34495E", font=("Arial", 10, "italic"))

def insert_tagged(line):
    line = line.strip()
    if not line:
        return
    line = line.replace("🟢", "[LOW]").replace("🟠", "[MEDIUM]").replace("🔴", "[HIGH]")

    if line.startswith("["):
        output_text.insert(tk.END, line + "\n", "timestamp")
    elif "SUCCESS" in line:
        output_text.insert(tk.END, line + "\n", "success")
    elif "FAILURE" in line:
        output_text.insert(tk.END, line + "\n", "alert")
    elif line.startswith("INFO") or line.startswith("NOTICE"):
        output_text.insert(tk.END, line + "\n", "explanation")
    else:
        output_text.insert(tk.END, line + "\n")
    output_text.see(tk.END)

def run_script(script_path, output_widget, message, progress_bar, estimated_runtime=30):
    global progress_bar_running, progress_thread, root
    def task():
        global progress_bar_running, progress_thread
        try:
            env = os.environ.copy()
            env["PYTHONPATH"] = os.path.join(BASE_DIR, "..")
            env["PYTHONUNBUFFERED"] = "1"

            output_widget.delete(1.0, tk.END)
            output_widget.insert(tk.END, message + "\n")
            output_widget.see(tk.END)

            progress_bar_running = False
            if progress_thread and progress_thread.is_alive():
                progress_thread.join()

            root.after(0, lambda: progress_bar.config(value=0))
            root.update_idletasks()

            process = subprocess.Popen(
                [PYTHON_EXEC, script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env
            )

            start_time = time.time()
            last_progress = 0
            progress_bar_running = True

            def update_progress():
                nonlocal last_progress
                while process.poll() is None and progress_bar_running:
                    elapsed_time = time.time() - start_time
                    progress = min((elapsed_time / estimated_runtime) * 100, 100)
                    if progress >= last_progress:
                        root.after(0, lambda p=progress: progress_bar.config(value=p))
                        last_progress = progress
                    time.sleep(0.5)
                if progress_bar_running:
                    root.after(0, lambda: progress_bar.config(value=100))

            progress_thread = threading.Thread(target=update_progress, daemon=True)
            progress_thread.start()

            for line in iter(process.stdout.readline, ''):
                root.after(0, lambda l=line: insert_tagged(l))
            for line in iter(process.stderr.readline, ''):
                root.after(0, lambda l=line: insert_tagged("ERROR: " + l))

        except Exception as e:
            error_message = f"\n\nERROR: {e}\n"
            root.after(0, lambda msg=error_message: insert_tagged(msg))

        finally:
            progress_bar_running = False
            root.after(0, lambda: progress_bar.config(value=100))

    progress_bar_running = False
    if progress_thread and progress_thread.is_alive():
        progress_thread.join()
    root.after(0, lambda: progress_bar.config(value=0))
    root.update_idletasks()

    threading.Thread(target=task, daemon=True).start()

def copy_firewall_batch():
    rules_file = os.path.join(tempfile.gettempdir(), "windows_firewall_rules.bat")
    if os.path.exists(rules_file):
        root.clipboard_clear()
        root.clipboard_append(rules_file)
        insert_tagged("\nCopied path to firewall rules batch file to clipboard.\n")
    else:
        insert_tagged("\nERROR: No firewall batch file found. Run scan first.\n")

title_label = tk.Label(root, text="System Monitoring Dashboard", font=("Arial", 16, "bold"), fg="white", bg="#2C3E50")
title_label.pack(pady=10)

progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
progress_bar.pack(pady=10)

def create_button(text, command, color):
    button_font = ("Segoe UI Emoji", 12, "bold") if IS_WINDOWS else ("Arial", 12, "bold")
    return tk.Button(button_frame, text=text, command=command, font=button_font, bg=color, fg="black",
                     width=25, justify="center", relief="raised", bd=4, padx=10, pady=5,
                     activebackground="#34495E", activeforeground="black")

firewall_script = os.path.join(BASE_DIR, "firewall_creation", "firewall_rule_gen_windows.py" if IS_WINDOWS else "firewall_rule_gen.py")
log_script = os.path.join(BASE_DIR, "log_monitoring", "windows_log_parsing.py" if IS_WINDOWS else "log_parsing.py")
vuln_script = os.path.join(BASE_DIR, "vulnerability_scan", "nmap_scan_windows.py" if IS_WINDOWS else "nmap_scan.py")

button_frame = tk.Frame(root, bg="#2C3E50")
button_frame.pack(pady=20, fill="x", expand=True)

firewall_label = "Run Firewall Monitoring 🔥" if IS_WINDOWS else "🔥 Run Firewall Monitoring"
copy_label = "Copy Firewall Command 📋" if IS_WINDOWS else "📋 Copy Firewall Command"
log_label = "Run Log Monitoring 🔍" if IS_WINDOWS else "🔍 Run Log Monitoring"
vuln_label = "Run Vulnerability Scan 🛡️ " if IS_WINDOWS else "🛡️ Run Vulnerability Scan"

firewall_btn = create_button(firewall_label, lambda: run_script(firewall_script, output_text, firewall_label, progress_bar, estimated_runtime=30), "#E74C3C")
firewall_btn.grid(row=0, column=0, padx=15, pady=5, sticky="ew")

copy_btn = create_button(copy_label, copy_firewall_batch, "#F1C40F")
copy_btn.grid(row=0, column=1, padx=15, pady=5, sticky="ew")

log_btn = create_button(log_label, lambda: run_script(log_script, output_text, log_label, progress_bar, estimated_runtime=30), "#3498DB")
log_btn.grid(row=1, column=0, padx=15, pady=5, sticky="ew")

vuln_btn = create_button(vuln_label, lambda: run_script(vuln_script, output_text, vuln_label, progress_bar, estimated_runtime=180), "#2ECC71")
vuln_btn.grid(row=1, column=1, padx=15, pady=5, sticky="ew")

button_frame.grid_columnconfigure(0, weight=1)
button_frame.grid_columnconfigure(1, weight=1)

root.mainloop()
