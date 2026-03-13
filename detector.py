# ============================================
# Adaptive Cyber Resilience and Automated
# Threat Neutralization System (ACRTS)
# Team  : Jahnavi Singh, Darsh Bindra,
#          Aayushi Malik, Mohini
# Repo  : https://github.com/jahnavi-37
# Version: 1.0
# ============================================

from __future__ import annotations

import re
from collections import defaultdict
from typing import List, Dict, Union

import config
from mitre_mapper import get_mitre_details
from risk_scorer import compute_risk_score


SQL_PATTERNS = [
    r"\bOR\s+1=1\b",
    r"UNION\s+SELECT",
    r"DROP\s+TABLE",
    r"INSERT\s+INTO",
    r"'\s+OR\s+'",
    r"--",
]


def detect_threats(entries: List[Dict[str, str]]) -> List[Dict[str, Union[str, int]]]:
    incidents: List[Dict[str, Union[str, int]]] = []

    failed_by_ip = defaultdict(int)
    apache_ports = defaultdict(set)
    ip_seen = defaultdict(int)

    for entry in entries:
        ip = entry.get("ip_address", "")
        if ip:
            ip_seen[ip] += 1

        # Windows brute force
        if entry.get("log_source") == "windows" and entry.get("EventID") == "4625":
            failed_by_ip[ip] += 1

        # Linux brute force
        if entry.get("log_source") == "linux" and "failed password" in entry.get("raw", "").lower():
            failed_by_ip[ip] += 1

        # Apache port scan candidate collection
        if entry.get("log_source") == "apache" and "scan?port=" in entry.get("raw", ""):
            match = re.search(r"port=(\d+)", entry.get("raw", ""))
            if match:
                apache_ports[ip].add(match.group(1))

    # Brute force detection
    for ip, count in failed_by_ip.items():
        if count >= config.BRUTE_FORCE_THRESHOLD:
            mitre = get_mitre_details("Brute Force")
            risk = compute_risk_score(
                "Brute Force", "HIGH", entries[0].get("timestamp", ""), ip, ip_seen
            )
            incidents.append(
                {
                    "timestamp": entries[0].get("timestamp", ""),
                    "log_source": "windows/linux",
                    "threat_type": "Brute Force",
                    "ip_address": ip,
                    "severity": risk["severity"],
                    "risk_score": risk["risk_score"],
                    "mitre_technique_id": mitre["technique_id"],
                    "mitre_technique_name": mitre["technique_name"],
                    "mitre_tactic": mitre["tactic"],
                    "action_taken": "PENDING",
                    "status": "DETECTED",
                }
            )

    # RDP tunneling and C2C/PrivEsc from windows entries
    for entry in entries:
        if entry.get("log_source") != "windows":
            continue

        ip = entry.get("ip_address", "")
        timestamp = entry.get("timestamp", "")

        if entry.get("EventID") == "4624" and entry.get("LogonType") == "10":
            mitre = get_mitre_details("RDP Tunneling")
            risk = compute_risk_score("RDP Tunneling", "CRITICAL", timestamp, ip, ip_seen)
            incidents.append(
                {
                    "timestamp": timestamp,
                    "log_source": "windows",
                    "threat_type": "RDP Tunneling",
                    "ip_address": ip,
                    "severity": risk["severity"],
                    "risk_score": risk["risk_score"],
                    "mitre_technique_id": mitre["technique_id"],
                    "mitre_technique_name": mitre["technique_name"],
                    "mitre_tactic": mitre["tactic"],
                    "action_taken": "PENDING",
                    "status": "DETECTED",
                }
            )

        if entry.get("EventID") == "4688":
            parent = entry.get("ParentProcess", "").lower()
            child = entry.get("ProcessName", "").lower()

            if parent == "powershell.exe" and child == "cmd.exe":
                mitre = get_mitre_details("C2C Activity")
                risk = compute_risk_score("C2C Activity", "CRITICAL", timestamp, ip, ip_seen)
                incidents.append(
                    {
                        "timestamp": timestamp,
                        "log_source": "windows",
                        "threat_type": "C2C Activity",
                        "ip_address": ip,
                        "severity": risk["severity"],
                        "risk_score": risk["risk_score"],
                        "mitre_technique_id": mitre["technique_id"],
                        "mitre_technique_name": mitre["technique_name"],
                        "mitre_tactic": mitre["tactic"],
                        "action_taken": "PENDING",
                        "status": "DETECTED",
                    }
                )

            if child in {"powershell.exe", "cmd.exe"}:
                mitre = get_mitre_details("Privilege Escalation")
                risk = compute_risk_score("Privilege Escalation", "HIGH", timestamp, ip, ip_seen)
                incidents.append(
                    {
                        "timestamp": timestamp,
                        "log_source": "windows",
                        "threat_type": "Privilege Escalation",
                        "ip_address": ip,
                        "severity": risk["severity"],
                        "risk_score": risk["risk_score"],
                        "mitre_technique_id": mitre["technique_id"],
                        "mitre_technique_name": mitre["technique_name"],
                        "mitre_tactic": mitre["tactic"],
                        "action_taken": "PENDING",
                        "status": "DETECTED",
                    }
                )

    # SQL injection detection in apache logs
    for entry in entries:
        if entry.get("log_source") != "apache":
            continue
        request = entry.get("request", "").upper()
        if any(re.search(pattern, request, re.IGNORECASE) for pattern in SQL_PATTERNS):
            ip = entry.get("ip_address", "")
            timestamp = entry.get("timestamp", "")
            mitre = get_mitre_details("SQL Injection")
            risk = compute_risk_score("SQL Injection", "HIGH", timestamp, ip, ip_seen)
            incidents.append(
                {
                    "timestamp": timestamp,
                    "log_source": "apache",
                    "threat_type": "SQL Injection",
                    "ip_address": ip,
                    "severity": risk["severity"],
                    "risk_score": risk["risk_score"],
                    "mitre_technique_id": mitre["technique_id"],
                    "mitre_technique_name": mitre["technique_name"],
                    "mitre_tactic": mitre["tactic"],
                    "action_taken": "PENDING",
                    "status": "DETECTED",
                }
            )

    # Port scanning detection in apache logs
    for ip, ports in apache_ports.items():
        if len(ports) >= config.PORT_SCAN_THRESHOLD:
            mitre = get_mitre_details("Port Scanning")
            risk = compute_risk_score(
                "Port Scanning", "MEDIUM", entries[0].get("timestamp", ""), ip, ip_seen
            )
            incidents.append(
                {
                    "timestamp": entries[0].get("timestamp", ""),
                    "log_source": "apache",
                    "threat_type": "Port Scanning",
                    "ip_address": ip,
                    "severity": risk["severity"],
                    "risk_score": risk["risk_score"],
                    "mitre_technique_id": mitre["technique_id"],
                    "mitre_technique_name": mitre["technique_name"],
                    "mitre_tactic": mitre["tactic"],
                    "action_taken": "PENDING",
                    "status": "DETECTED",
                }
            )

    return incidents
