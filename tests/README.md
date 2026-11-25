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

**Expected:** 56 rows scanned, 6 IP addresses, 3 threats found.

## Sample log (`data/sample_log.csv`)

| IP Address | Requests | Failed Logins | Expected result |
|---|---|---|---|
| 198.51.100.200 | 3 | 0 | Blacklisted IP |
| 198.51.100.23 | 28 | 0 | Flooding |
| 203.0.113.45 | 12 | 12 | Brute Force |
| 203.0.113.77 | 25 | 8 | Brute Force, Flooding, Blacklisted IP |

**Expected:** 143 rows scanned, 19 IP addresses, 4 threats found.

## Test an IP tab

Start the app (no file needed) and use **Add Activity** with these values.

| IP Address | Requests | Failed Logins | Expected result |
|---|---|---|---|
| 10.0.0.5 | 10 | 6 | Brute Force (6 > 5) |
| 10.0.0.6 | 21 | 0 | Flooding (21 > 20) |
| 10.0.0.7 | 20 | 5 | Normal (exactly at both limits) |
| 192.0.2.150 | 1 | 0 | Blacklisted IP |
| 999.1.1.1 | 1 | 0 | error: invalid IP address |
| 10.0.0.8 | 3 | 5 | error: failed logins cannot be more than requests |

Adding activity twice for the same IP adds up. For example 10.0.0.9 with 4 failed logins,
then 10.0.0.9 with 4 more, gives 8 failed logins and Brute Force.

## Blacklist tab

| Action | Expected result |
|---|---|
| Add 10.0.0.6 | saved to blacklist.csv, list count goes up by 1 |
| Add 203.0.113.77 again | message: already on the blacklist |
| Add abc | error: invalid IP address |
