import tkinter as tk
from tkinter import scrolledtext
import subprocess

# Function to run scripts and display output
def run_script(script_path, output_widget):
    try:
        result = subprocess.run(['python3', script_path], capture_output=True, text=True)
        output_widget.delete(1.0, tk.END)  # Clear previous text
        output_widget.insert(tk.END, result.stdout if result.stdout else "No output from script.")
    except Exception as e:
        output_widget.delete(1.0, tk.END)
        output_widget.insert(tk.END, f"Error: {e}")

# Create main window
root = tk.Tk()
root.title("System Monitoring Dashboard")
root.geometry("600x400")

# Title Label
title_label = tk.Label(root, text="System Monitoring Dashboard", font=("Arial", 14, "bold"))
title_label.pack(pady=10)

# Output Text Area
output_text = scrolledtext.ScrolledText(root, width=70, height=15, wrap=tk.WORD)
output_text.pack(pady=10)

# Buttons to Run Scripts
firewall_btn = tk.Button(root, text="Run Firewall Monitoring", command=lambda: run_script(".vscode/firewall_creation/firewall_rule_gen.py", output_text))
firewall_btn.pack(pady=5)

log_btn = tk.Button(root, text="Run Log Monitoring", command=lambda: run_script(".vscode/log_monitoring/log_parsing.py", output_text))
log_btn.pack(pady=5)

vuln_btn = tk.Button(root, text="Run Vulnerability Scan", command=lambda: run_script(".vscode/vulnerability_scan/nmap_scan.py", output_text))
vuln_btn.pack(pady=5)

# Run the Tkinter event loop
root.mainloop()