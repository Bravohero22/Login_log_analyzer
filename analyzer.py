import csv
import json

def is_private_ip(ip):
    if ip.startswith("192.168") or ip.startswith("10."):
        return True
    else:
        return False


def load_log(filename):
    rows = []
    skipped = 0

    with open(filename, "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row["status"] is None or row["status"] == "":
                print("skipping broken row")
                skipped += 1
                continue
            rows.append(row)
    return rows,skipped

def count_failures(rows):
    counts = {}
    for row in rows:
        if row["status"] == "failed":
            ip = row["ip"]
            if ip in counts:
                counts[ip] +=1
            else:
                counts[ip] = 1
    return counts

def find_brute_force(counts,threshold):
    suspects = []
    for ip, count in counts.items():
        if count >= threshold:
            suspects.append(ip)
    return suspects

def find_suspicious_logins(rows):
    suspicious = []
    for row in rows:
        if row["status"] == "success" and not is_private_ip(row["ip"]):
            suspicious.append({"username": row["username"], "ip" : row["ip"]})
    return suspicious

def save_report(findings, filename):
    with open(filename, "w") as file:
        json.dump(findings,file, indent=4)

rows, skipped = load_log("login_log.csv")
counts = count_failures(rows)
suspects = find_brute_force(counts, 5)
suspicious = find_suspicious_logins(rows)

findings = {
    "brute_force_suspects" : suspects,
    "suspicious_logins" : suspicious,
    "broken_rows_skipped" : skipped
}

save_report(findings, "report.json")

print("--- Login Log Report ---")
print(f"Brute-force suspects: {suspects}")
print(f"Suspicious Logins: {suspicious}")
print(f"Broken rows skipped: {skipped}")