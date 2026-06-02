with open('auth.log') as file:
    logs = file.readlines()
    FAILED_LOGIN_COUNT = 0
    SUCCESSFUL_LOGIN_COUNT = 0
    IP_ADDRESSES_TRACKER = {}
    for line in logs:
        if 'FAILED LOGIN' in line:
            FAILED_LOGIN_COUNT += 1
            
            PARTS = line.split()
            IP_ADDRESS = PARTS[3]
            print(IP_ADDRESS)

            if IP_ADDRESS in IP_ADDRESSES_TRACKER:
              IP_ADDRESSES_TRACKER[IP_ADDRESS] += 1
            else:
              IP_ADDRESSES_TRACKER[IP_ADDRESS] = 1

        elif 'SUCCESSFUL LOGIN' in line:
            SUCCESSFUL_LOGIN_COUNT += 1

print(f'Total Failed Logins: {FAILED_LOGIN_COUNT}')
print(f'Total Successful Logins: {SUCCESSFUL_LOGIN_COUNT}')
print("\nSuspicious IPs:")

with open("suspicious_ips.txt", "w") as output:

    for ip, count in IP_ADDRESSES_TRACKER.items():

        if count >= 5:
            message = f"CRITICAL ALERT: {ip} is performing a brute force attack with {count} failed attempts"

            print(message)
            output.write(message + "\n")

        elif count >= 3:
            message = f"{ip} had {count} failed login attempts"

            print(message)
            output.write(message + "\n")