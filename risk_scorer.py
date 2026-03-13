# ============================================
# Adaptive Cyber Resilience and Automated
# Threat Neutralization System (ACRTS)
# Team  : Jahnavi Singh, Darsh Bindra,
#          Aayushi Malik, Mohini
# Repo  : https://github.com/jahnavi-37
# Version: 1.0
# ============================================

from datetime import datetime
from typing import Dict, Union

BASE_SCORES = {
    "C2C Activity": 40,
    "RDP Tunneling": 40,
    "Brute Force": 30,
    "Privilege Escalation": 35,
    "SQL Injection": 25,
    "Port Scanning": 20,
}


def _parse_hour(ts: str) -> int:
    """Best-effort parse to hour; return -1 on failure."""
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%b %d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
        "%d/%b/%Y:%H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts, fmt).hour
        except ValueError:
            continue
    return -1


def _severity_from_score(score: int) -> str:
    if score <= 25:
        return "LOW"
    if score <= 50:
        return "MEDIUM"
    if score <= 75:
        return "HIGH"
    return "CRITICAL"


def compute_risk_score(threat_type: str, severity: str, timestamp: str, ip_address: str, ip_counts: Dict[str, int]) -> Dict[str, Union[int, str]]:
    """Compute risk score and adjusted severity based on rules."""
    score = BASE_SCORES.get(threat_type, 10)

    hour = _parse_hour(timestamp)
    if 0 <= hour <= 4:
        score += 20

    seen = ip_counts.get(ip_address, 1)
    if seen > 10:
        score += 40
    elif seen > 3:
        score += 25

    if severity.upper() == "CRITICAL":
        score += 15

    score = max(0, min(score, 100))
    adjusted_severity = _severity_from_score(score)
    return {"risk_score": score, "severity": adjusted_severity}
