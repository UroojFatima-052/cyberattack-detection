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
from datetime import datetime, timedelta
from tkinter import ttk, filedialog, messagebox

from detector import (read_log, read_blacklist, analyse, lookup_ip, is_valid_ip,
                      add_to_blacklist,
                      FAILED_LOGIN_LIMIT, REQUEST_LIMIT, PORT_LIMIT, BREAK_IN_FAILS)
from merge_sort import merge_sort

# ---------- dark theme colours ----------
BG = "#0b1220"          # window background
PANEL = "#101a2e"       # header and tab bar
CARD = "#15213a"        # cards, table, inputs
BORDER = "#22314f"
TEXT = "#e6edf7"
MUTED = "#8b9bb8"
ACCENT = "#22d3ee"      # cyan
ACCENT_DARK = "#0ea5c4"
DANGER = "#fb7185"      # threats
WARN = "#fbbf24"        # amber
SAFE = "#34d399"        # normal

# colour and order of each risk level (Critical first)
RISK_COLOUR = {"Critical": "#f43f5e", "High": "#fb923c", "Medium": WARN, "Safe": SAFE}
RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Safe": 3}

# ports used when the Test an IP tab makes rows (common ports first)
TEST_PORTS = [443, 22, 80, 21, 23, 25, 53, 110, 135, 139, 445, 3306, 3389, 8080]

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


def test_port(i, different_ports):
    """Port for the i-th test row, so the rows use exactly `different_ports` ports."""
    k = i % different_ports
    return TEST_PORTS[k] if k < len(TEST_PORTS) else 9000 + k


class DetectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyberattack Detection")
        self.root.geometry("1240x740")
        self.root.minsize(1100, 640)
        self.root.configure(bg=BG)

        self.rows = None            # log rows (from the file and/or test activity)
        self.rows_label_name = ""   # file name shown above the stat cards
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
        for i, (key, title, width, anchor) in enumerate(columns):
            table.heading(key, text=title, anchor=anchor)
            table.column(key, width=width, anchor=anchor, minwidth=60,
                         stretch=(i == len(columns) - 1))   # only the last column grows
        table.tag_configure("warn", foreground=WARN)
        for level, colour in RISK_COLOUR.items():
            table.tag_configure(level, foreground=colour)
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
        tk.Label(titles, text="Log analysis for brute force, flooding, port scans, break-ins and blacklisted IPs",
                 bg=PANEL, fg=MUTED, font=(FONT, 10)).pack(anchor="w")

        self.badge = tk.Label(header, text="  ●  NO SCAN YET  ", bg=CARD, fg=MUTED,
                              font=(FONT, 10, "bold"), padx=10, pady=6)
        self.badge.pack(side="right", padx=24)

    def _set_badge(self, threats, critical=0):
        if critical:
            word = "THREAT" if threats == 1 else "THREATS"
            self.badge.config(text=f"  \u25cf  {threats} {word}  |  {critical} CRITICAL  ",
                              bg="#3a1622", fg=RISK_COLOUR["Critical"])
        elif threats is None:
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
        cards = (("rows", "ROWS SCANNED"), ("ips", "IP ADDRESSES"),
                 ("threats", "THREATS FOUND"), ("critical", "CRITICAL (BREAK-IN)"),
                 ("blacklist", "BLACKLIST SIZE"))
        for i, (key, title) in enumerate(cards):
            stats.grid_columnconfigure(i, weight=1, uniform="stat")
            card = self._card(stats)
            card.grid(row=0, column=i, sticky="ew",
                      padx=(0 if i == 0 else 6, 0 if i == len(cards) - 1 else 6))
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
            ("ip", "IP ADDRESS", 135, "w"),
            ("risk", "RISK", 95, "w"),
            ("requests", "REQUESTS", 95, "center"),
            ("failed", "FAILED", 70, "center"),
            ("ports", "PORTS", 65, "center"),
            ("attacks", "ATTACK TYPE", 255, "w"),
            ("reason", "REASON", 420, "w"),
        ])

        rules = (f"RULES   failed logins > {FAILED_LOGIN_LIMIT} = Brute Force    "
                 f"requests > {REQUEST_LIMIT} = Flooding    "
                 f"different ports > {PORT_LIMIT} = Port Scan    "
                 f"login after {BREAK_IN_FAILS}+ fails in a row = Break-in    "
                 f"on blacklist = Blacklisted IP")
        tk.Label(page, text=rules, bg=BG, fg=MUTED, font=(FONT, 9)).pack(
            anchor="w", padx=24, pady=(10, 14))
        return page

    def _entry(self, parent, width, textvariable=None):
        return tk.Entry(parent, width=width, textvariable=textvariable,
                        bg=BG, fg=TEXT, insertbackground=ACCENT, relief="flat",
                        font=(MONO, 12), highlightthickness=1,
                        highlightbackground=BORDER, highlightcolor=ACCENT)

    def _build_test_tab(self):
        page = tk.Frame(self.pages, bg=BG)
        tk.Label(page, text="Add activity for any IP address. The rows are added to the log "
                            "(on top of rows already there) and the whole log is checked again.",
                 bg=BG, fg=MUTED, font=(FONT, 10)).pack(anchor="w", padx=24, pady=(20, 12))

        # input card
        form = self._card(page, fill="x", padx=24)
        inner = tk.Frame(form, bg=CARD)
        inner.pack(fill="x", padx=20, pady=16)

        self.req_var = tk.StringVar(value="10")
        self.fail_var = tk.StringVar(value="0")
        self.port_var = tk.StringVar(value="1")
        self.got_in_var = tk.BooleanVar(value=False)
        fields = tk.Frame(inner, bg=CARD)
        fields.pack(side="left")
        for col, (title, width, var) in enumerate((("IP ADDRESS", 18, None),
                                                   ("REQUESTS", 8, self.req_var),
                                                   ("FAILED LOGINS", 8, self.fail_var),
                                                   ("DIFFERENT PORTS", 8, self.port_var))):
            self._section_label(fields, title).grid(row=0, column=col, sticky="w",
                                                    padx=(0, 16), pady=(0, 6))
            entry = self._entry(fields, width, var)
            entry.grid(row=1, column=col, sticky="w", padx=(0, 16), ipady=7, ipadx=6)
            if col == 0:
                self.ip_entry = entry
        self.ip_entry.insert(0, "10.0.0.5")
        self.ip_entry.bind("<Return>", lambda e: self.add_activity())
        tk.Checkbutton(fields, text="Logged in successfully after the failed logins",
                       variable=self.got_in_var, bg=CARD, fg=TEXT, selectcolor=BG,
                       activebackground=CARD, activeforeground=TEXT, font=(FONT, 10),
                       highlightthickness=0, bd=0).grid(row=2, column=0, columnspan=4,
                                                        sticky="w", pady=(10, 0))

        ttk.Button(inner, text="Add Activity", style="Primary.TButton",
                   command=self.add_activity).pack(side="right", anchor="s")

        # result card (left) and examples (right)
        row = tk.Frame(page, bg=BG)
        row.pack(fill="both", expand=True, padx=24, pady=(18, 20))

        left = tk.Frame(row, bg=BG)
        left.pack(side="left", fill="both", expand=True)
        self._section_label(left, "RESULT", bg=BG).pack(anchor="w", pady=(0, 6))
        self.verdict_card = self._card(left, fill="both", expand=True)
        self.verdict_bar = tk.Frame(self.verdict_card, bg=BORDER, width=6)
        self.verdict_bar.pack(side="left", fill="y")
        body = tk.Frame(self.verdict_card, bg=CARD)
        body.pack(side="left", fill="both", expand=True, padx=22, pady=16)

        self.verdict_ip = tk.Label(body, text="No IP tested yet", bg=CARD, fg=TEXT,
                                   font=(MONO, 16, "bold"))
        self.verdict_ip.pack(anchor="w")
        self.verdict_text = tk.Label(body, text="Type an IP and click Add Activity",
                                     bg=CARD, fg=MUTED, font=(FONT, 18, "bold"),
                                     justify="left", wraplength=640)
        self.verdict_text.pack(anchor="w", pady=(2, 12))

        counts = tk.Frame(body, bg=CARD)
        counts.pack(anchor="w")
        self.verdict_counts = {}
        for key, title in (("requests", "REQUESTS"), ("failed", "FAILED LOGINS"),
                           ("ports", "DIFFERENT PORTS"), ("blacklisted", "ON BLACKLIST")):
            box = tk.Frame(counts, bg=CARD)
            box.pack(side="left", padx=(0, 32))
            self._section_label(box, title).pack(anchor="w")
            value = tk.Label(box, text="\u2013", bg=CARD, fg=TEXT, font=(FONT, 14, "bold"))
            value.pack(anchor="w")
            self.verdict_counts[key] = value

        self._section_label(body, "REASON").pack(anchor="w", pady=(16, 0))
        self.verdict_reason = tk.Label(body, text="\u2013", bg=CARD, fg=TEXT,
                                       font=(FONT, 11), justify="left", wraplength=640)
        self.verdict_reason.pack(anchor="w")

        right = tk.Frame(row, bg=BG)
        right.pack(side="right", fill="y", padx=(16, 0))
        self._section_label(right, "TRY THESE", bg=BG).pack(anchor="w", pady=(0, 6))
        tips = self._card(right, fill="both", expand=True)
        for setup, result, level in (
                ("10 requests, 6 failed", "Brute Force", "Medium"),
                ("21 requests, 0 failed", "Flooding", "Medium"),
                ("12 requests, 12 ports", "Port Scan", "Medium"),
                ("1 request from 192.0.2.150", "Blacklisted IP", "Medium"),
                ("25 requests, 7 failed", "Brute Force + Flooding", "High"),
                ("8 requests, 5 failed, tick logged in", "Break-in", "Critical"),
                ("20 requests, 5 failed, 10 ports", "nothing (at the limits)", "Safe")):
            item = tk.Frame(tips, bg=CARD)
            item.pack(fill="x", padx=16, pady=(8, 0))
            tk.Label(item, text=setup, bg=CARD, fg=TEXT, font=(MONO, 10)).pack(anchor="w")
            tk.Label(item, text=f"{level.upper()}  {result}", bg=CARD,
                     fg=RISK_COLOUR[level], font=(FONT, 9, "bold")).pack(anchor="w")
        tk.Frame(tips, bg=CARD, height=8).pack()
        return page

    def _build_blacklist_tab(self):
        page = tk.Frame(self.pages, bg=BG)
        tk.Label(page, text="IPs on this list are always reported as Blacklisted IP. "
                            "New IPs are saved to blacklist.csv.",
                 bg=BG, fg=MUTED, font=(FONT, 10)).pack(anchor="w", padx=24, pady=(20, 12))

        form = self._card(page, fill="x", padx=24)
        inner = tk.Frame(form, bg=CARD)
        inner.pack(fill="x", padx=20, pady=18)
        left = tk.Frame(inner, bg=CARD)
        left.pack(side="left")
        self._section_label(left, "IP ADDRESS").pack(anchor="w", pady=(0, 6))
        self.bl_entry = self._entry(left, 24)
        self.bl_entry.pack(anchor="w", ipady=7, ipadx=6)
        self.bl_entry.bind("<Return>", lambda e: self.add_blacklist())
        ttk.Button(inner, text="Add to Blacklist", style="Primary.TButton",
                   command=self.add_blacklist).pack(side="right", anchor="s")

        head = tk.Frame(page, bg=BG)
        head.pack(fill="x", padx=24, pady=(20, 6))
        self.bl_title = self._section_label(head, "", bg=BG)
        self.bl_title.pack(side="left")
        tk.Label(head, text="File: " + os.path.relpath(self.blacklist_path, app_folder()),
                 bg=BG, fg=MUTED,
                 font=(FONT, 9)).pack(side="right")

        table_card = self._card(page, fill="both", expand=True, padx=24, pady=(0, 20))
        self.bl_table = self._make_table(table_card, [
            ("no", "#", 60, "center"),
            ("ip", "IP ADDRESS", 240, "w"),
            ("seen", "IN LOADED LOG", 200, "w"),
        ])
        self.refresh_blacklist()
        return page

    def refresh_blacklist(self):
        """Show the blacklist (in file order) and whether each IP is in the log."""
        self.bl_title.config(text=f"BLACKLISTED IPS ({len(self.blacklist)})")
        self.bl_table.delete(*self.bl_table.get_children())
        for number, ip in enumerate(self.blacklist, start=1):
            seen = "–"
            if self.analysis is not None:
                result = lookup_ip(self.analysis, ip)
                seen = f"Yes, {result['requests']} requests" if result["found"] else "No"
            self.bl_table.insert("", "end", tags=("warn",), values=(number, ip, seen))

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
        self.rows_label_name = os.path.basename(path)
        self.file_label.config(text=f"{self.rows_label_name}   ({len(rows)} rows)")
        self.table.delete(*self.table.get_children())
        for key in ("rows", "ips", "threats", "critical"):
            self.stat_values[key].config(text="–", fg=TEXT)
        self._set_badge(None)
        self.refresh_blacklist()

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
        critical = [s for s in threats if s["risk"] == "Critical"]

        # most dangerous first: Merge Sort by risk level (stable, so IP order stays inside a level)
        threats = merge_sort(threats, key=lambda s: RISK_ORDER[s["risk"]])

        self.table.delete(*self.table.get_children())
        for s in threats:
            self.table.insert("", "end", tags=(s["risk"],), values=(
                s["ip"], "\u25cf " + s["risk"], s["requests"], s["failed"],
                s["different_ports"], ", ".join(s["attacks"]), s["reason"]))

        self.stat_values["rows"].config(text=str(len(self.rows)))
        self.stat_values["ips"].config(text=str(len(summaries)))
        self.stat_values["threats"].config(text=str(len(threats)),
                                           fg=DANGER if threats else SAFE)
        self.stat_values["critical"].config(
            text=str(len(critical)), fg=RISK_COLOUR["Critical"] if critical else SAFE)
        self.stat_values["blacklist"].config(text=str(len(self.blacklist)))
        self._set_badge(len(threats), len(critical))
        self.refresh_blacklist()
        if self.rows_label_name:
            self.file_label.config(text=f"{self.rows_label_name}   ({len(self.rows)} rows)")

    # ================= actions: Blacklist =================
    def add_blacklist(self):
        """Add to Blacklist button: save the IP to the file and check again."""
        ip = self.bl_entry.get().strip()
        if not is_valid_ip(ip):
            messagebox.showerror("Invalid IP address",
                                 "Please type a valid IP address, for example 203.0.113.50")
            return
        if ip in self.blacklist:
            messagebox.showinfo("Already blacklisted", f"{ip} is already on the blacklist.")
            return
        try:
            add_to_blacklist(self.blacklist_path, ip)
        except OSError:
            messagebox.showerror("Could not save",
                                 "The blacklist file could not be saved.")
            return

        self.blacklist.append(ip)
        self.bl_entry.delete(0, "end")
        if self.rows is not None and self.analysis is not None:
            self.run_scan()                   # check the log again with the new list
        self.stat_values["blacklist"].config(text=str(len(self.blacklist)))
        self.refresh_blacklist()

    # ================= actions: Test an IP =================
    def add_activity(self):
        """Add Activity button: add log rows for one IP, check again, show the verdict."""
        ip = self.ip_entry.get().strip()
        if not is_valid_ip(ip):
            messagebox.showerror("Invalid IP address",
                                 "Please type a valid IP address, for example 192.168.1.10")
            return
        try:
            requests = int(self.req_var.get())
            failed = int(self.fail_var.get())
            ports = int(self.port_var.get())
        except ValueError:
            messagebox.showerror("Invalid number",
                                 "Requests, failed logins and ports must be whole numbers.")
            return
        if requests < 1 or failed < 0 or failed > requests:
            messagebox.showerror("Invalid number",
                                 "Requests must be at least 1, and failed logins "
                                 "cannot be more than requests.")
            return
        if ports < 1 or ports > requests:
            messagebox.showerror("Invalid number",
                                 "Different ports must be at least 1 and cannot be "
                                 "more than requests (each request uses one port).")
            return
        got_in = self.got_in_var.get()
        if got_in and failed == requests:
            messagebox.showerror("Invalid number",
                                 "To log in after the failed logins, requests must be "
                                 "more than failed logins.")
            return

        if self.rows is None:                 # no file loaded: start an empty log
            self.rows = []
            self.rows_label_name = "test activity only"
        # Order of logins in time:
        #   ticked     -> failed logins first, then successful ones (attacker got in)
        #   not ticked -> successful logins first, then the failed ones
        if got_in:
            logins = ["Fail"] * failed + ["Success"] * (requests - failed)
        else:
            logins = ["Success"] * (requests - failed) + ["Fail"] * failed

        now = datetime.now()
        for i in range(requests):
            self.rows.append({
                "Time": (now + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S"),
                "IP Address": ip,
                "Port": str(test_port(i, ports)),
                "Login": logins[i],
            })

        self.run_scan()
        self.show_verdict(lookup_ip(self.analysis, ip))

    def show_verdict(self, result):
        """Fill the result card for one IP."""
        attacks = result["attacks"]
        risk = result["risk"]
        colour = RISK_COLOUR[risk]
        if attacks:
            text = f"{risk.upper()} RISK: " + ", ".join(attacks).upper()
        else:
            text = "SAFE: NO ATTACK FOUND"

        self.verdict_bar.config(bg=colour)
        self.verdict_ip.config(text=result["ip"])
        self.verdict_text.config(text=text, fg=colour)
        self.verdict_counts["requests"].config(text=str(result["requests"]))
        self.verdict_counts["failed"].config(text=str(result["failed"]))
        self.verdict_counts["ports"].config(text=str(result["different_ports"]))
        self.verdict_counts["blacklisted"].config(
            text="Yes" if result["blacklisted"] else "No",
            fg=WARN if result["blacklisted"] else TEXT)
        self.verdict_reason.config(text=result["reason"])


if __name__ == "__main__":
    root = tk.Tk()
    DetectionApp(root)
    root.mainloop()
