import tkinter as tk
from tkinter import scrolledtext, ttk
import subprocess
import threading
import os
import time

def run_script(script_path, output_widget, message, progress_bar):
    """Runs a script asynchronously with a dynamically updating progress bar while ensuring real-time log monitoring."""
    def task():
        try:
            env = os.environ.copy()
            env["PYTHONPATH"] = "/Users/estelledenis/IdeaSnapshots/system-monitor"
            
            output_widget.delete(1.0, tk.END)
            output_widget.insert(tk.END, message + "\n")
            output_widget.see(tk.END)
            
            # Reset progress bar
            progress_bar['value'] = 0
            root.update_idletasks()
            
            process = subprocess.Popen(
                [os.path.join(os.environ.get("VIRTUAL_ENV", "/Users/estelledenis/myenv"), "bin", "python"), script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env
            )
            
            start_time = time.time()
            estimated_runtime = 30  # Adjust based on real execution time
            
            def update_progress():
                while process.poll() is None:
                    elapsed_time = time.time() - start_time
                    progress = (elapsed_time / estimated_runtime) * 100
                    progress_bar['value'] = min(progress, 100)
                    root.update_idletasks()
                    time.sleep(0.5)  # Update every 0.5 seconds
                progress_bar['value'] = 100  # Ensure full completion
                root.update_idletasks()
            
            progress_thread = threading.Thread(target=update_progress, daemon=True)
            progress_thread.start()
            
            for line in iter(process.stdout.readline, ''):
                output_widget.insert(tk.END, line)
                output_widget.see(tk.END)
            for line in iter(process.stderr.readline, ''):
                output_widget.insert(tk.END, "ERROR: " + line)
                output_widget.see(tk.END)
            
        except Exception as e:
            output_widget.insert(tk.END, f"\n\nERROR: {e}\n")
        finally:
            progress_bar['value'] = 100  # Ensure full completion
            root.update_idletasks()
    
    threading.Thread(target=task, daemon=True).start()

# Create main window
root = tk.Tk()
root.title("System Monitoring Dashboard")
root.geometry("600x450")

# Title Label
title_label = tk.Label(root, text="System Monitoring Dashboard", font=("Arial", 14, "bold"))
title_label.pack(pady=10)

# Output Text Area
output_text = scrolledtext.ScrolledText(root, width=70, height=15, wrap=tk.WORD)
output_text.pack(pady=10)

# Progress Bar
progress_bar = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
progress_bar.pack(pady=10)

# Define script paths
firewall_script = "/Users/estelledenis/IdeaSnapshots/system-monitor/.vscode/firewall_creation/firewall_rule_gen.py"
log_script = "/Users/estelledenis/IdeaSnapshots/system-monitor/.vscode/log_monitoring/log_parsing.py"
vuln_script = "/Users/estelledenis/IdeaSnapshots/system-monitor/.vscode/vulnerability_scan/nmap_scan.py"

# Buttons to Run Scripts
firewall_btn = tk.Button(root, text="Run Firewall Monitoring", command=lambda: run_script(firewall_script, output_text, "🔥 Creating firewall rules...", progress_bar))
firewall_btn.pack(pady=5)

log_btn = tk.Button(root, text="Run Log Monitoring", command=lambda: run_script(log_script, output_text, "🔍 Running Log Monitoring...", progress_bar))
log_btn.pack(pady=5)

vuln_btn = tk.Button(root, text="Run Vulnerability Scan", command=lambda: run_script(vuln_script, output_text, "🛡️ Running Vulnerability Scan...", progress_bar))
vuln_btn.pack(pady=5)

# Run the Tkinter event loop
root.mainloop()
