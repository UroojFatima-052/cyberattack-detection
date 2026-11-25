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

**Expected:** 56 rows checked, 6 IP addresses, 3 suspicious.

## Sample log (`data/sample_log.csv`)

| IP Address | Requests | Failed Logins | Expected result |
|---|---|---|---|
| 198.51.100.200 | 3 | 0 | Blacklisted IP |
| 198.51.100.23 | 28 | 0 | Flooding |
| 203.0.113.45 | 12 | 12 | Brute Force |
| 203.0.113.77 | 25 | 8 | Brute Force, Flooding, Blacklisted IP |

**Expected:** 143 rows checked, 19 IP addresses, 4 suspicious.
