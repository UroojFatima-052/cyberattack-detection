# Cyberattack Detection

A small desktop application that checks a server log file and reports suspicious IP addresses.
Load a log file, click **Check**, and the table shows each suspicious IP, the type of attack
and the reason it was flagged.

## The window

| Tab | What it does |
|---|---|
| Scan Log | **Load File** and **Check**. Shows rows scanned, IP count, threats found, blacklist size, and a table of threats with the reason for each |
| Test an IP | Type any IP with a number of requests and failed logins, click **Add Activity**. The rows are added to the log, the whole log is checked again, and the result card shows the verdict and the reason |
| Blacklist | Shows every blacklisted IP. **Add to Blacklist** saves a new IP to `blacklist.csv` and checks the log again |

Course project for **Analysis of Algorithms**, SMI University, Karachi.

## What it detects

| Attack | Rule |
|---|---|
| Brute Force | more than 5 failed logins from one IP |
| Flooding | more than 20 requests from one IP |
| Blacklisted IP | the IP is on the list in `blacklist.csv` |

One IP can match more than one rule. Counts are taken over the whole file.

## Algorithms used

| Step | Algorithm | Purpose | Time complexity |
|---|---|---|---|
| 1 | Merge Sort | sort the log rows by IP address | O(n log n) |
| 2 | Merge Sort | sort the blacklist once | O(m log m) |
| 3 | Linear Scan (one pass, like Linear Search) | count failed logins and requests per IP | O(n) |
| 4 | Binary Search | check each IP against the sorted blacklist | O(log m) per IP |
| 5 | Binary Search | find one IP in the sorted results (Test an IP tab) | O(log k) |

n = number of log rows, m = number of blacklisted IPs, k = number of different IPs in the log.
Total: **O(n log n + m log m)**, which is **O(n log n)** when the blacklist is small.
Merge Sort needs **O(n)** extra memory.

All sorting and searching is written by us. No built-in `sort()` or `sorted()` is used.

## Project structure

```
cyberattack-detection/
├── data/
│   ├── sample_log.csv   sample log (143 rows) with normal and attack rows
│   └── blacklist.csv    known bad IPs (kept unsorted on purpose)
├── tests/
│   ├── edge_cases.csv   tests the exact limits (5 vs 6, 20 vs 21)
│   └── README.md        expected results
├── merge_sort.py        Merge Sort
├── binary_search.py     Binary Search
├── detector.py          reads the log, counts per IP, applies the rules
└── app.py               desktop window (Tkinter)
```

## Log file format

A CSV file with these four columns:

```
Time,IP Address,Port,Login
2026-11-25 09:00:06,192.168.1.24,443,Success
2026-11-25 09:01:12,203.0.113.45,22,Fail
```

`Login` is `Success` or `Fail`. Only `IP Address` and `Login` are used by the rules.

The sample data is made by us. Attack IPs come from the ranges reserved for
documentation (192.0.2.x, 198.51.100.x, 203.0.113.x), so no real person's IP is used.

## Run from source

Requires Python 3 (Tkinter is included with Python on Windows).

```
python app.py
```

## Build the .exe (Windows)

Install PyInstaller once:

```
pip install pyinstaller
```

Build from the project folder:

```
pyinstaller --onefile --windowed --name CyberattackDetection app.py
```

The file `CyberattackDetection.exe` is created in the `dist` folder.
Copy `data/blacklist.csv` into the same folder as the .exe, because the
program looks for `blacklist.csv` next to itself.

## Team

| Member | Part |
|---|---|
| Urooj Fatima | desktop window, connecting the modules, .exe |
| Lareb Ali | data file, blacklist, Merge Sort |
| Laraib | counting (Linear Scan), Binary Search |
| Wania Naeem | test cases, testing, report |
