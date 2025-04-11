import tkinter as tk
from tkinter import scrolledtext, ttk
import subprocess
import threading
import os
import time
import platform

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_PATH = os.path.join(BASE_DIR, "venv")
PYTHON_EXEC = os.path.join(
    VENV_PATH,
    "Scripts" if platform.system() == "Windows" else "bin",
    "python.exe" if platform.system() == "Windows" else "python"
)

if not os.path.exists(PYTHON_EXEC):
    raise FileNotFoundError(f"Python executable not found at {PYTHON_EXEC}")

progress_bar_running = False
progress_thread = None

root = tk.Tk()
root.title("System Monitoring Dashboard")
root.geometry("750x500")
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
    if line.startswith("🕒"):
        output_text.insert(tk.END, line + "\n", "timestamp")
    elif "[✅ SUCCESS]" in line:
        output_text.insert(tk.END, line + "\n", "success")
    elif "[❌ ALERT]" in line:
        output_text.insert(tk.END, line + "\n", "alert")
    elif "[✅ TOUCH ID]" in line:
        output_text.insert(tk.END, line + "\n", "touchid")
    elif line.startswith("ℹ️") or line.startswith("🔐"):
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
            output_widget.delete(1.0, tk.END)
            output_widget.insert(tk.END, message + "\n")
            output_widget.see(tk.END)
            progress_bar_running = False
            if progress_thread and progress_thread.is_alive():
                progress_thread.join()
            root.after(0, lambda: progress_bar.config(value=0))
            root.update_idletasks()
            process = subprocess.Popen([
                PYTHON_EXEC, script_path
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
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

def copy_pf_command():
    command = "sudo pfctl -f ~/Documents/block_ports.conf"
    root.clipboard_clear()
    root.clipboard_append(command)
    insert_tagged("\n✅ Copied firewall command to clipboard!\n")

title_label = tk.Label(root, text="System Monitoring Dashboard", font=("Arial", 16, "bold"), fg="white", bg="#2C3E50")
title_label.pack(pady=10)

progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
progress_bar.pack(pady=10)

def create_button(text, command, color):
    return tk.Button(button_frame, text=text, command=command, font=("Arial", 12, "bold"), bg=color, fg="black", relief="raised", bd=4, padx=10, pady=5, activebackground="#34495E", activeforeground="black")

firewall_script = os.path.join(BASE_DIR, "firewall_creation", "firewall_rule_gen_windows.py" if platform.system() == "Windows" else "firewall_rule_gen.py")
log_script = os.path.join(BASE_DIR, "log_monitoring", "windows_log_parsing.py" if platform.system() == "Windows" else "log_parsing.py")
vuln_script = os.path.join(BASE_DIR, "vulnerability_scan", "nmap_scan_windows.py" if platform.system() == "Windows" else "nmap_scan.py")

button_frame = tk.Frame(root, bg="#2C3E50")
button_frame.pack(pady=20)

firewall_btn = create_button("🔥 Run Firewall Monitoring", lambda: run_script(firewall_script, output_text, "🔥 Creating firewall rules...", progress_bar, estimated_runtime=30), "#E74C3C")
firewall_btn.grid(row=0, column=0, padx=15, pady=5, sticky="ew")

copy_btn = create_button("📋 Copy Firewall Command", copy_pf_command, "#F1C40F")
copy_btn.grid(row=0, column=1, padx=15, pady=5, sticky="ew")

log_btn = create_button("🔍 Run Log Monitoring", lambda: run_script(log_script, output_text, "🔍 Running Log Monitoring...", progress_bar, estimated_runtime=30), "#3498DB")
log_btn.grid(row=1, column=0, padx=15, pady=5, sticky="ew")

vuln_btn = create_button("🛡️ Run Vulnerability Scan", lambda: run_script(vuln_script, output_text, "🛡️ Running Vulnerability Scan...", progress_bar, estimated_runtime=180), "#2ECC71")
vuln_btn.grid(row=1, column=1, padx=15, pady=5, sticky="ew")

button_frame.grid_columnconfigure(0, weight=1)
button_frame.grid_columnconfigure(1, weight=1)

root.mainloop()

