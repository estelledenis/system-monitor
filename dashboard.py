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
    # Replace emoji risk markers with ASCII equivalents for compatibility
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

# (rest of file unchanged)
