# ============================================
# Adaptive Cyber Resilience and Automated
# Threat Neutralization System (ACRTS)
# Team  : Jahnavi Singh, Darsh Bindra,
#          Aayushi Malik, Mohini
# Repo  : https://github.com/jahnavi-37
# Version: 1.0
# ============================================

from __future__ import annotations

import sys
from collections import Counter

import config
import database
import log_parser
from detector import detect_threats
from responder import block_ip, terminate_process, send_email_alert

BANNER = """
=====================================================
  Adaptive Cyber Resilience and Automated
  Threat Neutralization System (ACRTS)
  Version : 1.0
  Team    : Jahnavi Singh | Darsh Bindra |
            Aayushi Malik | Mohini
  GitHub  : https://github.com/jahnavi-37
  Status  : Active and Monitoring
=====================================================
"""


def choose_log_path() -> list[str]:
    print("Select log source:")
    print("1. Windows Event Log")
    print("2. Linux Auth Log")
    print("3. Apache Access Log")
    print("4. Scan All Sample Logs")
    choice = input("Enter choice (1-4): ").strip()

    if choice == "1":
        return [config.WINDOWS_LOG]
    if choice == "2":
        return [config.LINUX_LOG]
    if choice == "3":
        return [config.APACHE_LOG]
    return [config.WINDOWS_LOG, config.LINUX_LOG, config.APACHE_LOG]


def handle_action(incident: dict) -> dict:
    action_taken = "NO ACTION"
    status = "DETECTED"

    if incident.get("severity") in {"HIGH", "CRITICAL"}:
        if incident.get("threat_type") in {"Brute Force", "Port Scanning", "SQL Injection", "RDP Tunneling", "C2C Activity"}:
            action_taken = block_ip(incident.get("ip_address", ""))
            status = "BLOCKED"
        elif incident.get("threat_type") == "Privilege Escalation":
            action_taken = terminate_process(incident.get("threat_type", ""))
            status = "BLOCKED"
    incident["action_taken"] = action_taken
    incident["status"] = status

    if incident.get("severity") in config.ALERT_ON_SEVERITY:
        send_email_alert(incident)

    return incident


def print_incident(incident: dict) -> None:
    print("[ACRTS ALERT]")
    print(f"Threat Type  : {incident.get('threat_type')}")
    print(f"MITRE ID     : {incident.get('mitre_technique_id')}")
    print(f"MITRE Tactic : {incident.get('mitre_tactic')}")
    print(f"IP Address   : {incident.get('ip_address')}")
    print(f"Severity     : {incident.get('severity')}")
    print(f"Risk Score   : {incident.get('risk_score')}/100")
    print(f"Action Taken : {incident.get('action_taken')}")
    print(f"Time         : {incident.get('timestamp')}")
    print()


def summarize(incidents: list[dict]) -> None:
    total = len(incidents)
    severities = Counter(inc["severity"] for inc in incidents)
    print(f"Total threats detected: {total}")
    print(
        f"Critical: {severities.get('CRITICAL', 0)}  High: {severities.get('HIGH', 0)}  "
        f"Medium: {severities.get('MEDIUM', 0)}  Low: {severities.get('LOW', 0)}"
    )
    print("Results saved to acrts.db")
    print("Run dashboard: streamlit run dashboard.py")


def main() -> None:
    print(BANNER)
    database.init_db()

    paths = choose_log_path()
    combined_entries: list[dict] = []
    for path in paths:
        parsed = log_parser.parse_log(path)
        combined_entries.extend(parsed)

    if not combined_entries:
        print("No log entries parsed. Exiting.")
        sys.exit(0)

    incidents = detect_threats(combined_entries)
    handled: list[dict] = []
    for incident in incidents:
        incident = handle_action(incident)
        database.save_incident(incident)
        print_incident(incident)
        handled.append(incident)

    summarize(handled)


if __name__ == "__main__":
    main()
