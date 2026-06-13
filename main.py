import sqlite3
import json

connection = sqlite3.connect("security_logs.db")
cursor = connection.cursor()

cursor.execute("DROP TABLE IF EXISTS login_attempts")
cursor.execute("DROP TABLE IF EXISTS alerts")

cursor.execute("""
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT,
    time TEXT,
    status TEXT,
    ip_address TEXT,
    username TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT,
    severity TEXT,
    ip_address TEXT,
    username TEXT,
    description TEXT
)
""")

with open("auth.log") as file:
    logs = file.readlines()

FAILED_LOGIN_COUNT = 0
SUCCESSFUL_LOGIN_COUNT = 0
IP_ADDRESSES_TRACKER = {}

for line in logs:
    parts = line.split()

    date = parts[0]
    time = parts[1]
    status = parts[2] + " " + parts[3]
    ip = parts[5]
    user = parts[7]

    cursor.execute("""
    INSERT INTO login_attempts (
        date,
        time,
        status,
        ip_address,
        username
    )
    VALUES (?, ?, ?, ?, ?)
    """, (date, time, status, ip, user))

    if "FAILED LOGIN" in line:
        FAILED_LOGIN_COUNT += 1

        if ip in IP_ADDRESSES_TRACKER:
            IP_ADDRESSES_TRACKER[ip] += 1
        else:
            IP_ADDRESSES_TRACKER[ip] = 1

    elif "SUCCESSFUL LOGIN" in line:
        SUCCESSFUL_LOGIN_COUNT += 1


print(f"Total Failed Logins: {FAILED_LOGIN_COUNT}")
print(f"Total Successful Logins: {SUCCESSFUL_LOGIN_COUNT}")
print("\nSuspicious IPs:")

with open("suspicious_ips.txt", "w") as output:
    for ip, count in IP_ADDRESSES_TRACKER.items():

        if count >= 5:
            severity = "CRITICAL"
            alert_type = "BRUTE FORCE"
            description = f"{ip} is performing a brute force attack with {count} failed attempts"
            message = f"{severity} ALERT: {description}"

            print(message)
            output.write(message + "\n")

            cursor.execute("""
            INSERT INTO alerts (
                alert_type,
                severity,
                ip_address,
                username,
                description
            )
            VALUES (?, ?, ?, ?, ?)
            """, (alert_type, severity, ip, "UNKNOWN", description))

        elif count >= 3:
            severity = "HIGH"
            alert_type = "SUSPICIOUS LOGIN ACTIVITY"
            description = f"{ip} had {count} failed login attempts"
            message = f"{severity} ALERT: {description}"

            print(message)
            output.write(message + "\n")

            cursor.execute("""
            INSERT INTO alerts (
                alert_type,
                severity,
                ip_address,
                username,
                description
            )
            VALUES (?, ?, ?, ?, ?)
            """, (alert_type, severity, ip, "UNKNOWN", description))


print("\nTop Attacking IP Addresses:")

cursor.execute("""
SELECT ip_address, COUNT(*) AS failed_attempts
FROM login_attempts
WHERE status = 'FAILED LOGIN'
GROUP BY ip_address
ORDER BY failed_attempts DESC
""")

rows = cursor.fetchall()

for row in rows:
    print("IP Address:", row[0], "| Failed Attempts:", row[1])


print("\nMost Targeted Users:")

cursor.execute("""
SELECT username, COUNT(*) AS failed_attempts
FROM login_attempts
WHERE status = 'FAILED LOGIN'
GROUP BY username
ORDER BY failed_attempts DESC
""")

rows = cursor.fetchall()

for row in rows:
    print("Username:", row[0], "| Failed Attempts:", row[1])


print("\nPossible Success After Failures:")

cursor.execute("""
SELECT ip_address, username, COUNT(*) AS failed_attempts
FROM login_attempts
WHERE status = 'FAILED LOGIN'
GROUP BY ip_address, username
HAVING failed_attempts >= 3
""")

failed_patterns = cursor.fetchall()

for ip, user, failed_attempts in failed_patterns:

    cursor.execute("""
    SELECT * FROM login_attempts
    WHERE ip_address = ?
    AND username = ?
    AND status = 'SUCCESSFUL LOGIN'
    """, (ip, user))

    success_rows = cursor.fetchall()

    if success_rows:
        severity = "CRITICAL"
        alert_type = "POSSIBLE ACCOUNT COMPROMISE"
        description = f"{ip} had {failed_attempts} failed attempts against {user}, then had a successful login"

        print(description)

        cursor.execute("""
        INSERT INTO alerts (
            alert_type,
            severity,
            ip_address,
            username,
            description
        )
        VALUES (?, ?, ?, ?, ?)
        """, (alert_type, severity, ip, user, description))


print("\nReading Windows Security Data:")

try:
    with open("windows_security_data.json", "r", encoding="utf-8-sig") as windows_file:
        windows_data = json.load(windows_file)

    computer_name = windows_data["ComputerName"]
    defender_status = windows_data["DefenderStatus"]
    local_admins = windows_data["LocalAdmins"]
    running_processes = windows_data["RunningProcesses"]

    print("Computer Name:", computer_name)
    print("Defender Status:", defender_status)
    print("Local Admins:", local_admins)
    print("Running Processes Count:", len(running_processes))

    if defender_status != "Running":
        cursor.execute("""
        INSERT INTO alerts (
            alert_type,
            severity,
            ip_address,
            username,
            description
        )
        VALUES (?, ?, ?, ?, ?)
        """, (
            "WINDOWS DEFENDER ISSUE",
            "HIGH",
            "LOCALHOST",
            "SYSTEM",
            "Windows Defender is not running properly"
        ))

except FileNotFoundError:
    print("windows_security_data.json not found yet. Run the PowerShell collector first.")

except json.JSONDecodeError:
    print("windows_security_data.json exists but is empty or invalid. Re-run windows_collector.ps1.")


connection.commit()


print("\nFinal Alerts From SQL Database:")

cursor.execute("SELECT * FROM alerts")
rows = cursor.fetchall()

for row in rows:
    print(row)


print("\nBuilding Correlated Incidents:")

INCIDENTS = []
RISK_SCORE = 0

cursor.execute("SELECT severity FROM alerts")
alert_severities = cursor.fetchall()

for severity in alert_severities:

    if severity[0] == "HIGH":
        RISK_SCORE += 40

    elif severity[0] == "CRITICAL":
        RISK_SCORE += 80


cursor.execute("""
SELECT * FROM alerts
WHERE alert_type = 'POSSIBLE ACCOUNT COMPROMISE'
""")

possible_compromises = cursor.fetchall()

for incident in possible_compromises:

    INCIDENT = {
        "IncidentType": "Possible Account Compromise",
        "Severity": "CRITICAL",
        "IP_Address": incident[3],
        "Username": incident[4],
        "Description": incident[5],
        "RiskScore": RISK_SCORE
    }

    INCIDENTS.append(INCIDENT)


cursor.execute("""
SELECT * FROM alerts
WHERE alert_type = 'BRUTE FORCE'
""")

brute_force_incidents = cursor.fetchall()

for incident in brute_force_incidents:

    INCIDENT = {
        "IncidentType": "Brute Force Attack",
        "Severity": "CRITICAL",
        "IP_Address": incident[3],
        "Username": incident[4],
        "Description": incident[5],
        "RiskScore": RISK_SCORE
    }

    INCIDENTS.append(INCIDENT)


print("\nCorrelated Incidents:\n")

for incident in INCIDENTS:
    print("Incident Type:", incident["IncidentType"])
    print("Severity:", incident["Severity"])
    print("IP Address:", incident["IP_Address"])
    print("Username:", incident["Username"])
    print("Risk Score:", incident["RiskScore"])
    print("Description:", incident["Description"])
    print()


with open("incident_report.txt", "w") as report:
    report.write("SOC INCIDENT REPORT\n")
    report.write("===================\n\n")

    report.write(f"Total Failed Logins: {FAILED_LOGIN_COUNT}\n")
    report.write(f"Total Successful Logins: {SUCCESSFUL_LOGIN_COUNT}\n\n")

    report.write("Alerts:\n")

    cursor.execute("SELECT alert_type, severity, ip_address, username, description FROM alerts")
    alerts = cursor.fetchall()

    for alert in alerts:
        report.write(f"\nAlert Type: {alert[0]}\n")
        report.write(f"Severity: {alert[1]}\n")
        report.write(f"IP Address: {alert[2]}\n")
        report.write(f"Username: {alert[3]}\n")
        report.write(f"Description: {alert[4]}\n")


with open("final_soc_report.txt", "w") as soc_report:
    soc_report.write("FINAL SOC INCIDENT REPORT\n")
    soc_report.write("=========================\n\n")

    soc_report.write(f"Total Risk Score: {RISK_SCORE}\n\n")

    soc_report.write("Correlated Incidents:\n\n")

    for incident in INCIDENTS:
        soc_report.write(f"Incident Type: {incident['IncidentType']}\n")
        soc_report.write(f"Severity: {incident['Severity']}\n")
        soc_report.write(f"IP Address: {incident['IP_Address']}\n")
        soc_report.write(f"Username: {incident['Username']}\n")
        soc_report.write(f"Risk Score: {incident['RiskScore']}\n")
        soc_report.write(f"Description: {incident['Description']}\n")
        soc_report.write("\n=========================\n\n")


connection.close()