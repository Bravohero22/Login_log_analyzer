# Login Log Analyzer

A Python script that reads a daily login log (CSV), flags possible brute-force attacks, and spots successful logins from outside the company network. It was built as a practice work ticket while learning Python for cybersecurity.

## The problem

The task, as a junior security analyst:

> Every morning the login log is exported as a CSV. Read it and report which IPs have too many failed logins (possible brute-force attack), and whether anyone logged in successfully from outside our network. Some rows in the export are broken, so the script must not crash on them. Save the findings to a file for review.

## What it does

1. Reads `login_log.csv` and skips broken rows (rows with a missing status), counting them
2. Counts failed logins per IP address
3. Flags any IP with **5 or more** failed logins as a brute-force suspect
4. Flags any **successful** login from a public (non-company) IP
5. Saves the findings to `report.json` and prints a summary

Company IPs are treated as private addresses starting with `192.168` or `10.`.

## Project structure

```
login-log-analyzer/
    analyzer.py      # the script
    login_log.csv    # sample login data (includes one broken row)
    report.json      # sample output, created when the script runs
    README.md
```

## How to run

1. Install [Python 3](https://www.python.org/downloads/)
2. Clone this repo and open the folder
3. Run:
   ```
   python analyzer.py
   ```

## Sample output

```
skipping broken row
--- Login Log Report ---
Brute-force suspects: ['203.0.113.7']
Suspicious Logins: [{'username': 'jdoe', 'ip': '8.8.4.4'}]
Broken rows skipped: 1
```

`report.json`:

```json
{
    "brute_force_suspects": [
        "203.0.113.7"
    ],
    "suspicious_logins": [
        {
            "username": "jdoe",
            "ip": "8.8.4.4"
        }
    ],
    "broken_rows_skipped": 1
}
```

## How the code is organized

| Function | Job |
|---|---|
| `is_private_ip(ip)` | Checks whether an IP belongs to the company network |
| `load_log(filename)` | Reads the CSV, returns the good rows and the number of skipped rows |
| `count_failures(rows)` | Returns a dictionary of failed logins per IP |
| `find_brute_force(counts, threshold)` | Returns IPs at or above the failure threshold |
| `find_suspicious_logins(rows)` | Returns successful logins from public IPs |
| `save_report(findings, filename)` | Saves the findings to a JSON file |

## What I learned

- Reading CSV files with `csv.DictReader` and handling broken rows safely
- Counting items with a dictionary
- Splitting a task into small functions that feed each other
- Saving results to JSON with `json.dump`
- Using `not` to reuse one function for the opposite question

## Possible improvements

- Take the file name and threshold from the command line
- Check failures within a time window instead of the whole day
- Read the private IP ranges from a settings file

## Note

All data in this repo is made-up sample data. No real logs or real company IPs are used.
