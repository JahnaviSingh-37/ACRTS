# ============================================
# Adaptive Cyber Resilience and Automated
# Threat Neutralization System (ACRTS)
# Team  : Jahnavi Singh, Darsh Bindra,
#          Aayushi Malik, Mohini
# Repo  : https://github.com/jahnavi-37
# Version: 1.0
# ============================================

import smtplib
from email.mime.text import MIMEText
from typing import Dict, Union

import config


def block_ip(ip: str) -> str:
    action = f"ACRTS ACTION: IP {ip} has been blocked"
    print(action)
    return "IP BLOCKED"


def terminate_process(process: str) -> str:
    action = f"ACRTS ACTION: Process {process} terminated"
    print(action)
    return "PROCESS TERMINATED"


def quarantine_file(file_path: str) -> str:
    action = f"ACRTS ACTION: File {file_path} quarantined"
    print(action)
    return "FILE QUARANTINED"


def send_email_alert(incident: Dict[str, Union[str, int]]) -> None:
    subject = f"ACRTS ALERT - {incident.get('severity')} - {incident.get('threat_type')}"
    body = f"""
============================================
ACRTS Threat Alert
Team: Jahnavi Singh, Darsh Bindra,
      Aayushi Malik, Mohini
============================================
Threat       : {incident.get('threat_type')}
MITRE ID     : {incident.get('mitre_technique_id')}
MITRE Tactic : {incident.get('mitre_tactic')}
IP Address   : {incident.get('ip_address')}
Severity     : {incident.get('severity')}
Risk Score   : {incident.get('risk_score')}/100
Time         : {incident.get('timestamp')}
Action Taken : {incident.get('action_taken')}
============================================
"""

    if config.DEMO_MODE:
        print(subject)
        print(body)
        return

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = config.EMAIL_SENDER
    msg["To"] = config.EMAIL_RECEIVER

    with smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT) as server:
        server.starttls()
        server.login(config.EMAIL_SENDER, config.EMAIL_PASSWORD)
        server.send_message(msg)
