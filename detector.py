"""
Detector

Reads the log file and finds suspicious IP addresses.
"""

import csv

from merge_sort import merge_sort
from binary_search import binary_search

# The four columns every log file must have
REQUIRED_COLUMNS = ["Time", "IP Address", "Port", "Login"]

# Detection limits (an IP is flagged only when it goes ABOVE the limit)
FAILED_LOGIN_LIMIT = 5   # more than 5 failed logins  -> Brute Force
REQUEST_LIMIT = 20       # more than 20 requests      -> Flooding


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
    """Count requests and failed logins of each IP in ONE pass.

    The rows must already be sorted by IP address (Merge Sort), so all
    rows of one IP are next to each other. We walk through the rows once,
    like Linear Search, and start a new count whenever the IP changes.

    Time complexity: O(n), where n is the number of rows.
    Returns a list of {"ip", "requests", "failed"} in IP order.
    """
    summaries = []
    current = None

    for row in sorted_rows:
        ip = row["IP Address"]

        if current is None or ip != current["ip"]:
            # A new IP starts here
            current = {"ip": ip, "requests": 0, "failed": 0}
            summaries.append(current)

        current["requests"] += 1
        if row["Login"] == "Fail":
            current["failed"] += 1

    return summaries


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

    if failed > FAILED_LOGIN_LIMIT:
        attacks.append("Brute Force")
        reasons.append(f"{failed} failed logins > {FAILED_LOGIN_LIMIT}")
    if requests > REQUEST_LIMIT:
        attacks.append("Flooding")
        reasons.append(f"{requests} requests > {REQUEST_LIMIT}")
    if on_blacklist:
        attacks.append("Blacklisted IP")
        reasons.append("IP is on the blacklist")

    if not attacks:
        return [], (f"{failed} failed logins (limit {FAILED_LOGIN_LIMIT}), "
                    f"{requests} requests (limit {REQUEST_LIMIT}), not on blacklist")
    return attacks, ";  ".join(reasons)


def analyse(rows, blacklist):
    """Check EVERY IP in the log.

    Steps:
      1. Merge Sort the rows by IP address        O(n log n)
      2. Merge Sort the blacklist (once)          O(m log m)
      3. One pass to count per IP (Linear Scan)   O(n)
      4. Binary Search each IP in the blacklist   O(log m) per IP

    Total: O(n log n + m log m), which is O(n log n) when the blacklist is small.

    Returns a dictionary:
      "summaries" : one entry per IP, sorted by IP, with counts, attacks and reason
      "ips"       : just the IPs, in the same sorted order (used for Binary Search)
      "blacklist" : the sorted blacklist
    """
    sorted_rows = merge_sort(rows, key=lambda row: row["IP Address"])
    sorted_blacklist = merge_sort(blacklist)
    summaries = count_per_ip(sorted_rows)

    for s in summaries:
        on_blacklist = binary_search(sorted_blacklist, s["ip"]) != -1
        s["blacklisted"] = on_blacklist
        s["attacks"], s["reason"] = explain(s, on_blacklist)
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
                "attacks": ", ".join(s["attacks"]),
                "reason": s["reason"],
            })
    return results, len(analysis["summaries"])
