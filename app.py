"""
Cyberattack Detection - desktop window (Tkinter)

Load a log file, click Check, and see the suspicious IP addresses.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog

from detector import read_log, read_blacklist, detect

# Colours (light theme)
BG = "#f5f7fb"
CARD = "#ffffff"
TEXT = "#1f2937"
MUTED = "#6b7280"
BORDER = "#e5e7eb"
PRIMARY = "#257de0"
PRIMARY_DARK = "#1b64be"
ALERT_ROW = "#fdecec"

FONT = "Segoe UI"


def app_folder():
    """Folder the program runs from (works for app.py and for the .exe)."""
    if getattr(sys, "frozen", False):          # running as .exe
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def find_blacklist():
    """Look for blacklist.csv next to the program, then inside data/."""
    for path in (os.path.join(app_folder(), "blacklist.csv"),
                 os.path.join(app_folder(), "data", "blacklist.csv")):
        if os.path.exists(path):
            return path
    return None


class DetectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyberattack Detection")
        self.root.geometry("920x600")
        self.root.minsize(760, 480)
        self.root.configure(bg=BG)

        self.rows = None            # log rows of the loaded file

        self._setup_styles()
        self._build_header()
        self._build_toolbar()
        self._build_table()
        self._build_footer()

    # ---------- look and feel ----------
    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("Primary.TButton", font=(FONT, 10, "bold"),
                        foreground="white", background=PRIMARY,
                        borderwidth=0, padding=(18, 8))
        style.map("Primary.TButton",
                  background=[("active", PRIMARY_DARK), ("disabled", "#a9c8ef")])

        style.configure("Secondary.TButton", font=(FONT, 10),
                        foreground=TEXT, background=CARD,
                        bordercolor=BORDER, borderwidth=1, padding=(18, 8))
        style.map("Secondary.TButton", background=[("active", "#eef2f7")])

        style.configure("Treeview", font=(FONT, 10), rowheight=30,
                        background=CARD, fieldbackground=CARD,
                        foreground=TEXT, bordercolor=BORDER, borderwidth=0)
        style.configure("Treeview.Heading", font=(FONT, 10, "bold"),
                        background="#eef2f7", foreground=TEXT,
                        relief="flat", padding=(8, 6))
        style.map("Treeview", background=[("selected", "#d6e6fa")],
                  foreground=[("selected", TEXT)])

        style.configure("Vertical.TScrollbar", background="#e5e7eb",
                        troughcolor=CARD, bordercolor=CARD, arrowcolor=MUTED)

    # ---------- layout ----------
    def _build_header(self):
        header = tk.Frame(self.root, bg=CARD, highlightbackground=BORDER,
                          highlightthickness=1)
        header.pack(fill="x")
        tk.Label(header, text="Cyberattack Detection", bg=CARD, fg=TEXT,
                 font=(FONT, 18, "bold")).pack(anchor="w", padx=24, pady=(16, 0))
        tk.Label(header, text="Find suspicious IP addresses in a server log file",
                 bg=CARD, fg=MUTED, font=(FONT, 10)).pack(anchor="w", padx=24, pady=(2, 16))

    def _build_toolbar(self):
        bar = tk.Frame(self.root, bg=BG)
        bar.pack(fill="x", padx=24, pady=(18, 10))

        self.load_button = ttk.Button(bar, text="Load File", style="Secondary.TButton",
                                      command=self.load_file)
        self.load_button.pack(side="left")

        self.check_button = ttk.Button(bar, text="Check", style="Primary.TButton",
                                       command=self.check)
        self.check_button.pack(side="left", padx=(10, 0))

        self.file_label = tk.Label(bar, text="No file loaded", bg=BG, fg=MUTED,
                                   font=(FONT, 10))
        self.file_label.pack(side="left", padx=(16, 0))

    def _build_table(self):
        card = tk.Frame(self.root, bg=CARD, highlightbackground=BORDER,
                        highlightthickness=1)
        card.pack(fill="both", expand=True, padx=24)

        columns = ("ip", "requests", "failed", "attacks")
        self.table = ttk.Treeview(card, columns=columns, show="headings")
        headings = {
            "ip": ("IP Address", 200, "w"),
            "requests": ("Requests", 110, "center"),
            "failed": ("Failed Logins", 130, "center"),
            "attacks": ("Attack Type", 320, "w"),
        }
        for col, (title, width, anchor) in headings.items():
            self.table.heading(col, text=title, anchor=anchor)
            self.table.column(col, width=width, anchor=anchor)
        self.table.tag_configure("alert", background=ALERT_ROW)

        scroll = ttk.Scrollbar(card, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _build_footer(self):
        footer = tk.Frame(self.root, bg=BG)
        footer.pack(fill="x", padx=24, pady=(10, 16))

        self.status_label = tk.Label(footer, text="Load a log file to begin.",
                                     bg=BG, fg=TEXT, font=(FONT, 10, "bold"))
        self.status_label.pack(anchor="w")

        rules = ("Rules:  more than 5 failed logins = Brute Force   |   "
                 "more than 20 requests = Flooding   |   IP on blacklist = Blacklisted IP")
        tk.Label(footer, text=rules, bg=BG, fg=MUTED,
                 font=(FONT, 9)).pack(anchor="w", pady=(4, 0))

    # ---------- button actions ----------
    def load_file(self):
        """Load File button: let the user pick a CSV log file."""
        path = filedialog.askopenfilename(
            title="Choose a log file",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if path:
            self.load_path(path)

    def load_path(self, path):
        """Read the log file and remember its rows."""
        self.rows = read_log(path)
        self.file_label.config(text=f"{os.path.basename(path)}  ({len(self.rows)} rows)",
                               fg=TEXT)
        self.table.delete(*self.table.get_children())
        self.status_label.config(text="File loaded. Click Check to find suspicious IPs.")

    def check(self):
        """Check button: run the detector and fill the results table."""
        blacklist = read_blacklist(find_blacklist())
        results, total_ips = detect(self.rows, blacklist)

        self.table.delete(*self.table.get_children())
        for r in results:
            self.table.insert("", "end", tags=("alert",),
                              values=(r["ip"], r["requests"], r["failed"], r["attacks"]))

        self.status_label.config(
            text=f"{len(self.rows)} rows checked  |  {total_ips} IP addresses  |  "
                 f"{len(results)} suspicious"
        )


if __name__ == "__main__":
    root = tk.Tk()
    DetectionApp(root)
    root.mainloop()
