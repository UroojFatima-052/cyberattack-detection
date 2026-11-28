# Test cases

Load `edge_cases.csv` in the app and click **Check**. It tests the exact limits of the rules.

| IP Address | What it does | Expected result |
|---|---|---|
| 192.168.1.50 | 3 normal requests | not shown (normal) |
| 192.0.2.10 | exactly 5 failed logins | not shown (5 is not more than 5) |
| 192.0.2.11 | 6 failed logins | Brute Force |
| 192.0.2.20 | exactly 20 requests | not shown (20 is not more than 20) |
| 192.0.2.21 | 21 requests | Flooding |
| 192.0.2.150 | 1 request, but on the blacklist | Blacklisted IP |
| 192.0.2.30 | exactly 10 different ports | not shown (10 is not more than 10) |
| 192.0.2.31 | 11 different ports | Port Scan |
| 192.0.2.40 | 4 failed logins in a row, then a success | not shown (needs 5 in a row) |
| 192.0.2.41 | 5 failed logins in a row, then a success | Break-in (Critical) |

**Expected:** 88 rows scanned, 10 IP addresses, 5 threats found, 1 critical.

## Sample log (`data/sample_log.csv`)

| IP Address | Requests | Failed Logins | Expected result |
|---|---|---|---|
| 198.51.100.200 | 3 | 0 | Blacklisted IP |
| 198.51.100.23 | 28 | 0 | Flooding |
| 203.0.113.45 | 12 | 12 | Brute Force |
| 203.0.113.77 | 25 | 8 | Brute Force, Flooding, Blacklisted IP (High) |
| 203.0.113.88 | 12 | 2 | Port Scan (12 different ports) |
| 192.0.2.66 | 9 | 6 | Break-in, Brute Force (Critical): 6 failed logins in a row, then a success |

All others are Medium unless marked.

**Expected:** 164 rows scanned, 21 IP addresses, 6 threats found, 1 critical.

## Test an IP tab

Start the app (no file needed) and use **Add Activity** with these values.
Ports is 1 and the "logged in" box is not ticked unless written.

| IP Address | Requests | Failed | Other | Expected result |
|---|---|---|---|---|
| 10.0.0.1 | 10 | 6 | | Medium: Brute Force (6 > 5) |
| 10.0.0.2 | 21 | 0 | | Medium: Flooding (21 > 20) |
| 10.0.0.3 | 12 | 0 | 12 ports | Medium: Port Scan (12 > 10) |
| 192.0.2.150 | 1 | 0 | | Medium: Blacklisted IP |
| 10.0.0.4 | 25 | 7 | | High: Brute Force, Flooding |
| 10.0.0.5 | 8 | 5 | ticked | Critical: Break-in |
| 10.0.0.6 | 20 | 5 | 10 ports | Safe (exactly at all limits) |
| 10.0.0.7 | 8 | 4 | ticked | Safe (only 4 failed in a row) |
| 999.1.1.1 | 1 | 0 | | error: invalid IP address |
| 10.0.0.8 | 3 | 5 | | error: failed logins cannot be more than requests |
| 10.0.0.9 | 3 | 0 | 5 ports | error: ports cannot be more than requests |
| 10.0.0.9 | 3 | 3 | ticked | error: needs at least one successful login |

Adding activity twice for the same IP adds up. For example 10.0.0.9 with 4 failed logins,
then 10.0.0.9 with 4 more, gives 8 failed logins and Brute Force.

## Blacklist tab

| Action | Expected result |
|---|---|
| Add 10.0.0.6 | saved to blacklist.csv, list count goes up by 1 |
| Add 203.0.113.77 again | message: already on the blacklist |
| Add abc | error: invalid IP address |
