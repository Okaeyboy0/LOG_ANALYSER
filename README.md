# Log File Reader

## Objective
Build a Python script that reads a log file and detects failed login attempts.

## Your Script Must:
- Open and read a text log file
- Loop through every line
- Detect lines containing:
  FAILED LOGIN
- Print suspicious lines
- Count total failed logins

## Example Log Data
2026-05-24 10:22:11 SUCCESS admin
2026-05-24 10:25:44 FAILED root
2026-05-24 10:28:01 FAILED guest

## Skills Practiced
- file reading
- loops
- conditions
- string searching
- parsing text

## Cybersecurity Relevance
SOC analysts constantly inspect authentication logs for suspicious activity.

## Bonus Challenges
- count failed logins per user
- count failed logins per IP
- highlight repeated attacks