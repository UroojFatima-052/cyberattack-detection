"""
Cyberattack Detection - desktop window (Tkinter)

Three tabs:
  Scan Log    load a log file and check it
  Test an IP  add activity for any IP and see how the app judges it
  Blacklist   view the blacklist and add new IPs to it
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from detector import (read_log, read_blacklist, analyse,
                      FAILED_LOGIN_LIMIT, REQUEST_LIMIT)

# ---------- dark theme colours ----------
BG = "#0b1220"          # window background
PANEL = "#101a2e"       # header and tab bar
CARD = "#15213a"        # cards, table, inputs
BORDER = "#22314f"
TEXT = "#e6edf7"
MUTED = "#8b9bb8"
ACCENT = "#22d3ee"      # cyan
ACCENT_DARK = "#0ea5c4"
DANGER = "#fb7185"      # attacks
WARN = "#fbbf24"        # blacklisted only
SAFE = "#34d399"        # normal

FONT = "Segoe UI"
MONO = "Consolas"


def app_folder():
    """Folder the program runs from (works for app.py and for the .exe)."""
    if getattr(sys, "frozen", False):          # running as .exe
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def find_blacklist_path():
    """Use blacklist.csv next to the program, then inside data/.
    If neither exists, a new one will be created next to the program."""
    for path in (os.path.join(app_folder(), "blacklist.csv"),
                 os.path.join(app_folder(), "data", "blacklist.csv")):
        if os.path.exists(path):
            return path
    return os.path.join(app_folder(), "blacklist.csv")


def row_tag(attacks):
    """Colour of a table row: red for attacks, amber for blacklisted only."""
    if "Brute Force" in attacks or "Flooding" in attacks:
        return "danger"
    if attacks:
        return "warn"
    return "safe"


class DetectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyberattack Detection")
        self.root.geometry("1180x740")
        self.root.minsize(980, 620)
        self.root.configure(bg=BG)

        self.rows = None            # log rows (from the file and/or test activity)
        self.analysis = None        # result of the last scan
        self.blacklist_path = find_blacklist_path()
        self.blacklist = (read_blacklist(self.blacklist_path)
                          if os.path.exists(self.blacklist_path) else [])

        self._setup_styles()
        self._build_header()
        self._build_tabs()
        self.show_tab("scan")

    # ================= look and feel =================
    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("Primary.TButton", font=(FONT, 10, "bold"),
                        foreground=BG, background=ACCENT, borderwidth=0,
                        focuscolor=ACCENT, padding=(20, 9))
        style.map("Primary.TButton", background=[("active", ACCENT_DARK)])

        style.configure("Secondary.TButton", font=(FONT, 10),
                        foreground=TEXT, background=CARD, bordercolor=BORDER,
                        lightcolor=CARD, darkcolor=CARD, borderwidth=1,
                        focuscolor=CARD, padding=(20, 9))
        style.map("Secondary.TButton", background=[("active", BORDER)])

        style.configure("Treeview", font=(FONT, 10), rowheight=32,
                        background=CARD, fieldbackground=CARD, foreground=TEXT,
                        bordercolor=BORDER, lightcolor=CARD, darkcolor=CARD,
                        borderwidth=0)
        style.configure("Treeview.Heading", font=(FONT, 9, "bold"),
                        background=PANEL, foreground=MUTED, relief="flat",
                        bordercolor=BORDER, lightcolor=PANEL, darkcolor=PANEL,
                        padding=(10, 8))
        style.map("Treeview.Heading", background=[("active", PANEL)])
        style.map("Treeview", background=[("selected", "#1e3a5f")],
                  foreground=[("selected", TEXT)])

        for name in ("TScrollbar", "Vertical.TScrollbar"):
            style.configure(name, background=BORDER, troughcolor=CARD,
                            bordercolor=CARD, lightcolor=BORDER, darkcolor=BORDER,
                            arrowcolor=MUTED, gripcount=0)
            style.map(name, background=[("active", MUTED)])

    def _card(self, parent, **pack):
        card = tk.Frame(parent, bg=CARD, highlightbackground=BORDER,
                        highlightthickness=1)
        if pack:
            card.pack(**pack)
        return card

    def _section_label(self, parent, text, bg=CARD):
        return tk.Label(parent, text=text, bg=bg, fg=MUTED, font=(FONT, 9, "bold"))

    def _make_table(self, parent, columns):
        """columns: list of (key, title, width, anchor)."""
        table = ttk.Treeview(parent, columns=[c[0] for c in columns], show="headings")
        for key, title, width, anchor in columns:
            table.heading(key, text=title, anchor=anchor)
            table.column(key, width=width, anchor=anchor, minwidth=60)
        table.tag_configure("danger", foreground=DANGER)
        table.tag_configure("warn", foreground=WARN)
        table.tag_configure("safe", foreground=SAFE)
        scroll = ttk.Scrollbar(parent, orient="vertical", command=table.yview)
        table.configure(yscrollcommand=scroll.set)
        table.pack(side="left", fill="both", expand=True, padx=(1, 0), pady=1)
        scroll.pack(side="right", fill="y")
        return table

    # ================= header =================
    def _build_header(self):
        header = tk.Frame(self.root, bg=PANEL)
        header.pack(fill="x")

        logo = tk.Canvas(header, width=44, height=48, bg=PANEL, highlightthickness=0)
        logo.pack(side="left", padx=(24, 12), pady=16)
        shield = [22, 3, 41, 10, 39, 28, 22, 45, 5, 28, 3, 10]
        logo.create_polygon(shield, fill="#0f2a3a", outline=ACCENT, width=2)
        logo.create_line(14, 24, 20, 31, 31, 17, fill=ACCENT, width=3,
                         capstyle="round", joinstyle="round")

        titles = tk.Frame(header, bg=PANEL)
        titles.pack(side="left")
        tk.Label(titles, text="CYBERATTACK DETECTION", bg=PANEL, fg=TEXT,
                 font=(FONT, 17, "bold")).pack(anchor="w")
        tk.Label(titles, text="Log analysis for brute force, flooding and blacklisted IPs",
                 bg=PANEL, fg=MUTED, font=(FONT, 10)).pack(anchor="w")

        self.badge = tk.Label(header, text="  ●  NO SCAN YET  ", bg=CARD, fg=MUTED,
                              font=(FONT, 10, "bold"), padx=10, pady=6)
        self.badge.pack(side="right", padx=24)

    def _set_badge(self, threats):
        if threats is None:
            self.badge.config(text="  ●  NO SCAN YET  ", bg=CARD, fg=MUTED)
        elif threats == 0:
            self.badge.config(text="  ●  NO THREATS FOUND  ", bg="#0f2e26", fg=SAFE)
        else:
            word = "THREAT" if threats == 1 else "THREATS"
            self.badge.config(text=f"  ●  {threats} {word} FOUND  ",
                              bg="#3a1622", fg=DANGER)

    # ================= tabs =================
    def _build_tabs(self):
        bar = tk.Frame(self.root, bg=PANEL)
        bar.pack(fill="x")
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x")

        self.tab_buttons = {}
        for key, title in (("scan", "Scan Log"), ("test", "Test an IP"),
                           ("blacklist", "Blacklist")):
            holder = tk.Frame(bar, bg=PANEL)
            holder.pack(side="left", padx=(24 if key == "scan" else 4, 4))
            label = tk.Label(holder, text=title, bg=PANEL, fg=MUTED,
                             font=(FONT, 11, "bold"), padx=8, pady=10, cursor="hand2")
            label.pack()
            line = tk.Frame(holder, bg=PANEL, height=3)
            line.pack(fill="x")
            label.bind("<Button-1>", lambda e, k=key: self.show_tab(k))
            self.tab_buttons[key] = (label, line)

        self.pages = tk.Frame(self.root, bg=BG)
        self.pages.pack(fill="both", expand=True)
        self.pages.grid_rowconfigure(0, weight=1)
        self.pages.grid_columnconfigure(0, weight=1)

        self.tab_frames = {
            "scan": self._build_scan_tab(),
            "test": self._build_test_tab(),
            "blacklist": self._build_blacklist_tab(),
        }
        for frame in self.tab_frames.values():
            frame.grid(row=0, column=0, sticky="nsew")

    def show_tab(self, key):
        for k, (label, line) in self.tab_buttons.items():
            active = k == key
            label.config(fg=ACCENT if active else MUTED)
            line.config(bg=ACCENT if active else PANEL)
        self.tab_frames[key].tkraise()

    # ================= tab 1: Scan Log =================
    def _build_scan_tab(self):
        page = tk.Frame(self.pages, bg=BG)

        # file + buttons
        top = tk.Frame(page, bg=BG)
        top.pack(fill="x", padx=24, pady=(20, 14))
        info = tk.Frame(top, bg=BG)
        info.pack(side="left")
        self._section_label(info, "LOG FILE", bg=BG).pack(anchor="w")
        self.file_label = tk.Label(info, text="No file loaded", bg=BG, fg=TEXT,
                                   font=(MONO, 11))
        self.file_label.pack(anchor="w", pady=(2, 0))
        ttk.Button(top, text="Check", style="Primary.TButton",
                   command=self.check).pack(side="right")
        ttk.Button(top, text="Load File", style="Secondary.TButton",
                   command=self.load_file).pack(side="right", padx=(0, 10))

        # stat cards
        stats = tk.Frame(page, bg=BG)
        stats.pack(fill="x", padx=24)
        self.stat_values = {}
        for i, (key, title) in enumerate((("rows", "ROWS SCANNED"),
                                          ("ips", "IP ADDRESSES"),
                                          ("threats", "THREATS FOUND"),
                                          ("blacklist", "BLACKLIST SIZE"))):
            stats.grid_columnconfigure(i, weight=1, uniform="stat")
            card = self._card(stats)
            card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 6, 0 if i == 3 else 6))
            self._section_label(card, title).pack(anchor="w", padx=16, pady=(12, 0))
            value = tk.Label(card, text="–", bg=CARD, fg=TEXT, font=(FONT, 22, "bold"))
            value.pack(anchor="w", padx=16, pady=(0, 10))
            self.stat_values[key] = value
        self.stat_values["blacklist"].config(text=str(len(self.blacklist)))

        # results table
        head = tk.Frame(page, bg=BG)
        head.pack(fill="x", padx=24, pady=(18, 6))
        self._section_label(head, "DETECTED THREATS", bg=BG).pack(side="left")
        table_card = self._card(page, fill="both", expand=True, padx=24)
        self.table = self._make_table(table_card, [
            ("ip", "IP ADDRESS", 150, "w"),
            ("requests", "REQUESTS", 85, "center"),
            ("failed", "FAILED LOGINS", 105, "center"),
            ("attacks", "ATTACK TYPE", 250, "w"),
            ("reason", "REASON", 420, "w"),
        ])

        rules = (f"RULES   failed logins > {FAILED_LOGIN_LIMIT} = Brute Force     "
                 f"requests > {REQUEST_LIMIT} = Flooding     IP on blacklist = Blacklisted IP")
        tk.Label(page, text=rules, bg=BG, fg=MUTED, font=(FONT, 9)).pack(
            anchor="w", padx=24, pady=(10, 14))
        return page

    def _build_test_tab(self):
        page = tk.Frame(self.pages, bg=BG)
        return page

    def _build_blacklist_tab(self):
        page = tk.Frame(self.pages, bg=BG)
        return page

    # ================= actions: Scan Log =================
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
        try:
            rows = read_log(path)
        except ValueError as error:          # wrong columns or empty file
            messagebox.showerror("Could not load file", str(error))
            return
        except (OSError, UnicodeDecodeError):
            messagebox.showerror("Could not load file",
                                 "This file could not be read. Please choose a CSV log file.")
            return

        self.rows = rows
        self.analysis = None
        self.file_label.config(text=f"{os.path.basename(path)}   ({len(rows)} rows)")
        self.table.delete(*self.table.get_children())
        for key in ("rows", "ips", "threats"):
            self.stat_values[key].config(text="–", fg=TEXT)
        self._set_badge(None)

    def check(self):
        """Check button: scan the loaded rows."""
        if self.rows is None:
            messagebox.showinfo("No file loaded", "Please load a log file first.")
            return
        self.run_scan()

    def run_scan(self):
        """Run the detector on the current rows and refresh the Scan Log tab."""
        self.analysis = analyse(self.rows, self.blacklist)
        summaries = self.analysis["summaries"]
        threats = [s for s in summaries if s["attacks"]]

        self.table.delete(*self.table.get_children())
        for s in threats:
            self.table.insert("", "end", tags=(row_tag(s["attacks"]),), values=(
                s["ip"], s["requests"], s["failed"], ", ".join(s["attacks"]), s["reason"]))

        self.stat_values["rows"].config(text=str(len(self.rows)))
        self.stat_values["ips"].config(text=str(len(summaries)))
        self.stat_values["threats"].config(text=str(len(threats)),
                                           fg=DANGER if threats else SAFE)
        self.stat_values["blacklist"].config(text=str(len(self.blacklist)))
        self._set_badge(len(threats))


if __name__ == "__main__":
    root = tk.Tk()
    DetectionApp(root)
    root.mainloop()
