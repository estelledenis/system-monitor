import tkinter as tk
from tkinter import scrolledtext, ttk
import subprocess
import threading
import os
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Global variables
progress_bar_running = False  # Tracks progress updates
progress_thread = None  # Holds the progress update thread

# Create main window (✅ Define root before functions use it)
root = tk.Tk()
root.title("System Monitoring Dashboard")
root.geometry("650x500")
root.configure(bg="#2C3E50")

def run_script(script_path, output_widget, message, progress_bar, estimated_runtime=30):
    """Runs a script asynchronously with a properly resetting and finishing progress bar."""
    global progress_bar_running, progress_thread, root  # ✅ Ensure root is accessible

    def task():
        global progress_bar_running, progress_thread  # ✅ Ensure modifications affect global variables
        try:
            env = os.environ.copy()
            env["PYTHONPATH"] = os.path.join(BASE_DIR, "..")

            output_widget.delete(1.0, tk.END)
            output_widget.insert(tk.END, message + "\n")
            output_widget.see(tk.END)

            # Stop previous progress thread before starting a new one
            progress_bar_running = False
            if progress_thread and progress_thread.is_alive():
                progress_thread.join()  # ✅ Ensure previous thread is stopped

            # Reset progress bar
            root.after(0, lambda: progress_bar.config(value=0))
            root.update_idletasks()

            process = subprocess.Popen(
                [os.path.join(os.environ.get("VIRTUAL_ENV", os.path.join(BASE_DIR, "../../../myenv")), "bin", "python"), script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env
            )

            start_time = time.time()
            last_progress = 0  # Track last progress value

            progress_bar_running = True  # Mark progress tracking as active

            def update_progress():
                """Continuously update the progress bar until the script finishes."""
                nonlocal last_progress
                while process.poll() is None and progress_bar_running:  # Check flag before updating
                    elapsed_time = time.time() - start_time
                    progress = min((elapsed_time / estimated_runtime) * 100, 100)
                    if progress >= last_progress:  # Ensure progress moves forward only
                        root.after(0, lambda p=progress: progress_bar.config(value=p))
                        last_progress = progress
                    time.sleep(0.5)

                # Ensure it reaches 100% when script is done
                if progress_bar_running:
                    root.after(0, lambda: progress_bar.config(value=100))

            # Start a new progress bar update thread
            progress_thread = threading.Thread(target=update_progress, daemon=True)  # ✅ Assign thread
            progress_thread.start()

            # Process script output in real-time
            for line in iter(process.stdout.readline, ''):
                root.after(0, lambda l=line: output_widget.insert(tk.END, l))
                root.after(0, output_widget.see, tk.END)
            for line in iter(process.stderr.readline, ''):
                root.after(0, lambda l=line: output_widget.insert(tk.END, "ERROR: " + l))
                root.after(0, output_widget.see, tk.END)

        except Exception as e:
            error_message = f"\n\nERROR: {e}\n"  # Capture error message in a variable
            root.after(0, lambda msg=error_message: output_widget.insert(tk.END, msg))

        finally:
            # Ensure progress stops properly when script finishes
            progress_bar_running = False
            root.after(0, lambda: progress_bar.config(value=100))

    # Stop and reset the progress bar before starting a new script
    progress_bar_running = False
    if progress_thread and progress_thread.is_alive():  # ✅ Ensure thread exists before checking
        progress_thread.join()  # Stop previous thread before resetting
    root.after(0, lambda: progress_bar.config(value=0))
    root.update_idletasks()
    
    # Start the script in a separate thread
    threading.Thread(target=task, daemon=True).start()

# Title Label
title_label = tk.Label(root, text="System Monitoring Dashboard", font=("Arial", 16, "bold"), fg="white", bg="#2C3E50")
title_label.pack(pady=10)

# Output Text Area
output_text = scrolledtext.ScrolledText(root, width=75, height=15, wrap=tk.WORD, bg="#ECF0F1", fg="#2C3E50", font=("Arial", 10))
output_text.pack(pady=10, padx=10)

# Progress Bar
progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
progress_bar.pack(pady=10)

# Button Styles
def create_button(text, command, color):
    return tk.Button(root, text=text, command=command, font=("Arial", 12, "bold"), bg=color, fg="black", relief="raised", bd=4, padx=10, pady=5, activebackground="#34495E", activeforeground="black")

# Define script paths
firewall_script = os.path.join(BASE_DIR, "firewall_creation/firewall_rule_gen.py")
log_script = os.path.join(BASE_DIR, "log_monitoring/log_parsing.py")
vuln_script = os.path.join(BASE_DIR, "vulnerability_scan/nmap_scan.py")

# Buttons to Run Scripts
firewall_btn = create_button("🔥 Run Firewall Monitoring", lambda: run_script(firewall_script, output_text, "🔥 Creating firewall rules...", progress_bar, estimated_runtime=30), "#E74C3C")
firewall_btn.pack(pady=5, fill=tk.X, padx=20)

log_btn = create_button("🔍 Run Log Monitoring", lambda: run_script(log_script, output_text, "🔍 Running Log Monitoring...", progress_bar, estimated_runtime=30), "#3498DB")
log_btn.pack(pady=5, fill=tk.X, padx=20)

vuln_btn = create_button("🛡️ Run Vulnerability Scan", lambda: run_script(vuln_script, output_text, "🛡️ Running Vulnerability Scan...", progress_bar, estimated_runtime=180), "#2ECC71")
vuln_btn.pack(pady=5, fill=tk.X, padx=20)

# Run the Tkinter event loop
root.mainloop()
