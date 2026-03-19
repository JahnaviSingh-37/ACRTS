# ============================================
# Adaptive Cyber Resilience and Automated
# Threat Neutralization System (ACRTS)
# Team  : Jahnavi Singh, Darsh Bindra,
#          Aayushi Malik, Mohini
# Repo  : https://github.com/jahnavi-37
# Version: 1.0
# ============================================

MITRE_MAPPING = {
    "Brute Force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversary attempts to gain access by guessing credentials",
    },
    "RDP Tunneling": {
        "technique_id": "T1021.001",
        "technique_name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": "Adversary uses RDP to move laterally through the network",
    },
    "SQL Injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public Facing Application",
        "tactic": "Initial Access",
        "description": "Adversary exploits weakness in web application",
    },
    "Port Scanning": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversary scans network to discover available services",
    },
    "Privilege Escalation": {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversary exploits software to gain higher privileges",
    },
    "C2C Activity": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversary uses standard protocols for command and control",
    },
    "Reconnaissance Whisper": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": "Adversary quietly maps the application surface with low-frequency probes",
    },
}


def get_mitre_details(threat_type: str) -> dict:
    """Return MITRE mapping for a threat type or a default placeholder."""
    return MITRE_MAPPING.get(
        threat_type,
        {
            "technique_id": "N/A",
            "technique_name": "Unknown",
            "tactic": "Unknown",
            "description": "No mapping available",
        },
    )
