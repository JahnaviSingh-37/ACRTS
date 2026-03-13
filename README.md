# ACRTS - Adaptive Cyber Resilience and Automated Threat Neutralization System
We built a small thing that watches logs, maps stuff to MITRE, and shouts when it sees trouble.

## Team
| Name | Role |
| Jahnavi Singh | Lead Developer & System Architect |
| Darsh Bindra | Backend Developer & Detection Engine |
| Aayushi Malik | Database & Report Module Developer |
| Mohini | Dashboard & Frontend Developer |

## About This Project
We are cybersecurity students doing our minor project. We wanted something hands-on while we were learning incident response in class. Jahnavi handled the main system and architecture. The rest of us kept poking at logs and UI until it worked.

## What It Does
Parses plain text logs, spots common attacks, maps them to MITRE, saves them to SQLite, and shows them in a Streamlit dashboard. It also prints demo response actions so we can walk through playbooks in class.

## MITRE ATT&CK Mapping
MITRE is that huge list of attacker tactics and techniques. We mapped the detections to IDs so we remember which tactic matches what.

| Attack | MITRE ID | Tactic |
| Brute Force | T1110 | Credential Access |
| RDP Tunneling | T1021.001 | Lateral Movement |
| SQL Injection | T1190 | Initial Access |
| Port Scanning | T1046 | Discovery |
| Privilege Escalation | T1068 | Privilege Escalation |
| C2C Activity | T1071 | Command and Control |

## Features
- Parses Windows event-like text, Linux auth logs, and Apache access logs.
- Detects brute force, RDP tunneling, C2C process chains, SQL injection, port scanning, and privilege escalation.
- Scores risk with time-of-day and IP repetition bumps.
- Saves everything to SQLite so nothing gets lost between runs.
- Streamlit dashboard with charts, MITRE columns, and a quick PDF download.

## Tech Stack
Python 3, SQLite, Streamlit, pandas, Altair, fpdf2. No admin rights needed on Mac.

## How It Works
We ask you which log to read, parse it, run the detection rules, score risk, take a demo action (like "block"), store it in the database, and then you can open the dashboard to see everything.

## Project Structure
```
main.py               # CLI engine
log_parser.py         # parses different log formats
sample_logs/          # fake logs for demo
config.py             # settings and thresholds
mitre_mapper.py       # MITRE mapping
risk_scorer.py        # risk scoring rules
detector.py           # detection logic
responder.py          # demo response actions
database.py           # SQLite helper
report_generator.py   # PDF report
dashboard.py          # Streamlit UI
requirements.txt      # deps
README.md             # this doc
```

## Installation and Running
1. Clone or download this repo on your Mac.
2. Create a venv if you like; we usually just `python -m venv .venv && source .venv/bin/activate`.
3. `pip install -r requirements.txt`.
4. `python main.py` to run detections. We mostly use option 4 to scan all sample logs.
5. `streamlit run dashboard.py` to open the dashboard. Keep the terminal open because Streamlit needs it.
6. If you want a PDF, use the download button in the dashboard after you have incidents.

## Sample Logs
`sample_logs/` has Windows-style event lines, Linux sshd lines, and Apache access hits with fake attacks. The log parsing part gave us a headache at first, but now it is just plain text so it stays Mac-friendly.

## What We Learned
We spent a lot of time tuning regex and counts. Streamlit is actually really fun to work with. Risk scoring is harder than it looks when you only have log lines.

## Future Ideas
- Add GeoIP and ASN context for the IPs.
- Hook in a real mail sender when not in demo mode.
- Add more web attack patterns and maybe DNS logs.

## Contact
GitHub: https://github.com/jahnavi-37  
Raise an issue for any problems. Also feel free to use this or suggest improvements.
