"""
Detector

Reads the log file and finds suspicious IP addresses.
"""

import csv
import os

from merge_sort import merge_sort
from binary_search import binary_search

# The four columns every log file must have
REQUIRED_COLUMNS = ["Time", "IP Address", "Port", "Login"]

# Detection limits (an IP is flagged only when it goes ABOVE the limit)
FAILED_LOGIN_LIMIT = 5   # more than 5 failed logins  -> Brute Force
REQUEST_LIMIT = 20       # more than 20 requests      -> Flooding
PORT_LIMIT = 10          # more than 10 different ports -> Port Scan
BREAK_IN_FAILS = 5       # a Success right after 5 or more failed logins in a row -> Break-in


def read_log(path):
    """Read the log CSV file and return a list of rows (dictionaries).

    Raises ValueError with a clear message if the file is not in the
    expected format, so the window can show it to the user.
    """
    rows = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)

        if reader.fieldnames is None:
            raise ValueError("The file is empty.")

        columns = [name.strip() for name in reader.fieldnames]
        missing = [c for c in REQUIRED_COLUMNS if c not in columns]
        if missing:
            raise ValueError(
                "This is not a valid log file.\n"
                "Missing column(s): " + ", ".join(missing) + "\n"
                "Required columns: " + ", ".join(REQUIRED_COLUMNS)
            )

        for raw in reader:
            # Clean up spaces around column names and values
            row = {k.strip(): (v or "").strip() for k, v in raw.items() if k}
            if not row.get("IP Address"):
                continue  # skip empty lines
            row["Login"] = row["Login"].capitalize()  # "fail"/"FAIL" -> "Fail"
            rows.append(row)

    if not rows:
        raise ValueError("The file has no log rows to check.")
    return rows


def count_per_ip(sorted_rows):
    """Count everything we need for each IP in ONE pass.

    The rows must already be sorted by IP address and then by time
    (Merge Sort), so all rows of one IP are next to each other and in
    time order. We walk through the rows once, like Linear Search, and
    start a new count whenever the IP changes.

    For each IP we count:
      requests     number of rows
      failed       number of failed logins
      streak       failed logins in a row, right now
      break_in     size of the fail streak before a Success (0 = no break-in)
      ports        every port the IP used (counted later)

    Time complexity: O(n), where n is the number of rows.
    Returns a list of dictionaries in IP order.
    """
    summaries = []
    current = None

    for row in sorted_rows:
        ip = row["IP Address"]

        if current is None or ip != current["ip"]:
            # A new IP starts here
            current = {"ip": ip, "requests": 0, "failed": 0,
                       "streak": 0, "break_in": 0, "ports": []}
            summaries.append(current)

        current["requests"] += 1
        current["ports"].append(row["Port"])

        if row["Login"] == "Fail":
            current["failed"] += 1
            current["streak"] += 1
        else:
            # A Success right after 5 or more failed logins in a row
            if current["streak"] >= BREAK_IN_FAILS and current["break_in"] == 0:
                current["break_in"] = current["streak"]
            current["streak"] = 0

    return summaries


def count_different(sorted_items):
    """Count how many DIFFERENT values a sorted list has, in one pass.

    Because the list is sorted, equal values are next to each other,
    so a new value starts whenever an item is not equal to the one before.
    Example: [22, 22, 80, 443, 443] -> 3
    Time complexity: O(p), where p is the length of the list.
    """
    count = 0
    for i in range(len(sorted_items)):
        if i == 0 or sorted_items[i] != sorted_items[i - 1]:
            count += 1
    return count


def read_blacklist(path):
    """Read the blacklist CSV (one IP per row, header "IP Address")."""
    blacklist = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        for line in csv.reader(f):
            if not line:
                continue
            ip = line[0].strip()
            if ip and ip != "IP Address":
                blacklist.append(ip)
    return blacklist


def explain(summary, on_blacklist):
    """Decide the attack types of one IP and say WHY in plain words.

    Returns (attacks, reason), for example
    (["Brute Force"], "12 failed logins > 5").
    """
    attacks = []
    reasons = []
    failed = summary["failed"]
    requests = summary["requests"]
    ports = summary["different_ports"]

    if summary["break_in"]:
        attacks.append("Break-in")
        reasons.append(f"logged in after {summary['break_in']} failed logins in a row")
    if failed > FAILED_LOGIN_LIMIT:
        attacks.append("Brute Force")
        reasons.append(f"{failed} failed logins > {FAILED_LOGIN_LIMIT}")
    if requests > REQUEST_LIMIT:
        attacks.append("Flooding")
        reasons.append(f"{requests} requests > {REQUEST_LIMIT}")
    if ports > PORT_LIMIT:
        attacks.append("Port Scan")
        reasons.append(f"{ports} ports > {PORT_LIMIT}")
    if on_blacklist:
        attacks.append("Blacklisted IP")
        reasons.append("on the blacklist")

    if not attacks:
        return [], (f"{failed} failed logins (limit {FAILED_LOGIN_LIMIT}), "
                    f"{requests} requests (limit {REQUEST_LIMIT}), "
                    f"{ports} ports (limit {PORT_LIMIT}), not on blacklist")
    return attacks, ", ".join(reasons)


def risk_level(attacks):
    """How dangerous an IP is.

    Critical : Break-in (the attacker got in)
    High     : 2 or more attacks
    Medium   : 1 attack
    Safe     : no attack
    """
    if "Break-in" in attacks:
        return "Critical"
    if len(attacks) >= 2:
        return "High"
    if len(attacks) == 1:
        return "Medium"
    return "Safe"


def analyse(rows, blacklist):
    """Check EVERY IP in the log.

    Steps:
      1. Merge Sort the rows by IP address, then time   O(n log n)
      2. Merge Sort the blacklist (once)                O(m log m)
      3. One pass to count per IP (Linear Scan)         O(n)
      4. Merge Sort each IP's ports, then count the
         different ones in one pass                     O(n log n) in total
      5. Binary Search each IP in the blacklist         O(log m) per IP

    Total: O(n log n + m log m), which is O(n log n) when the blacklist is small.

    Returns a dictionary:
      "summaries" : one entry per IP, sorted by IP, with counts, attacks and reason
      "ips"       : just the IPs, in the same sorted order (used for Binary Search)
      "blacklist" : the sorted blacklist
    """
    sorted_rows = merge_sort(rows, key=lambda row: (row["IP Address"], row["Time"]))
    sorted_blacklist = merge_sort(blacklist)
    summaries = count_per_ip(sorted_rows)

    for s in summaries:
        s["different_ports"] = count_different(merge_sort(s["ports"]))
        on_blacklist = binary_search(sorted_blacklist, s["ip"]) != -1
        s["blacklisted"] = on_blacklist
        s["attacks"], s["reason"] = explain(s, on_blacklist)
        s["risk"] = risk_level(s["attacks"])
        s["found"] = True

    return {
        "summaries": summaries,
        "ips": [s["ip"] for s in summaries],
        "blacklist": sorted_blacklist,
    }


def detect(rows, blacklist):
    """Return (results, total_ips): only the suspicious IPs, with reasons."""
    analysis = analyse(rows, blacklist)
    results = []
    for s in analysis["summaries"]:
        if s["attacks"]:
            results.append({
                "ip": s["ip"],
                "requests": s["requests"],
                "failed": s["failed"],
                "ports": s["different_ports"],
                "risk": s["risk"],
                "attacks": ", ".join(s["attacks"]),
                "reason": s["reason"],
            })
    return results, len(analysis["summaries"])


def lookup_ip(analysis, ip):
    """Find one IP in the analysis using Binary Search.

    analysis["ips"] is already sorted (Merge Sort), so the search is
    O(log k), where k is the number of different IPs in the log.
    If the IP is not in the log, we still check the blacklist.
    """
    index = binary_search(analysis["ips"], ip)
    if index != -1:
        return analysis["summaries"][index]

    on_blacklist = binary_search(analysis["blacklist"], ip) != -1
    return {
        "ip": ip,
        "requests": 0,
        "failed": 0,
        "different_ports": 0,
        "break_in": 0,
        "blacklisted": on_blacklist,
        "attacks": ["Blacklisted IP"] if on_blacklist else [],
        "risk": "Medium" if on_blacklist else "Safe",
        "reason": ("Not in the log, but the IP is on the blacklist" if on_blacklist
                   else "No activity from this IP in the log, and not on the blacklist"),
        "found": False,
    }


def is_valid_ip(ip):
    """True if ip looks like an IPv4 address, e.g. 192.168.1.10."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or int(part) > 255 or (len(part) > 1 and part[0] == "0"):
            return False
    return True


def add_to_blacklist(path, ip):
    """Add one IP to the end of the blacklist file (creates the file if needed)."""
    needs_header = not os.path.exists(path) or os.path.getsize(path) == 0
    needs_newline = False
    if not needs_header:
        with open(path, "rb") as f:
            f.seek(-1, os.SEEK_END)
            needs_newline = f.read(1) not in (b"\n", b"\r")

    with open(path, "a", newline="", encoding="utf-8") as f:
        if needs_header:
            f.write("IP Address\n")
        elif needs_newline:
            f.write("\n")
        f.write(ip + "\n")
