"""
Detector

Reads the log file and finds suspicious IP addresses.
"""

import csv

# The four columns every log file must have
REQUIRED_COLUMNS = ["Time", "IP Address", "Port", "Login"]


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
