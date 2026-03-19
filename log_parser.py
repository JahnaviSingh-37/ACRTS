# ============================================
# Adaptive Cyber Resilience and Automated
# Threat Neutralization System (ACRTS)
# Team  : Jahnavi Singh, Darsh Bindra,
#          Aayushi Malik, Mohini
# Repo  : https://github.com/jahnavi-37
# Version: 1.0
# ============================================

from __future__ import annotations

import os
from datetime import datetime
from typing import List, Dict, Union


def _detect_type(lines: List[str]) -> str:
    sample = " ".join(lines[:3]).lower()
    if "eventid=" in sample:
        return "windows"
    if "sshd" in sample:
        return "linux"
    if "http/1.1" in sample:
        return "apache"
    return "unknown"


def _parse_windows_line(line: str) -> Dict[str, str]:
    parts = line.strip().split()
    if len(parts) < 3:
        return {}
    timestamp = " ".join(parts[0:2])
    fields = {"timestamp": timestamp, "raw": line.strip(), "log_source": "windows"}
    for token in parts[2:]:
        if "=" in token:
            key, value = token.split("=", 1)
            fields[key] = value
    fields["ip_address"] = fields.get("SourceIP", "")
    return fields


def _parse_linux_line(line: str) -> Dict[str, str]:
    parts = line.strip().split()
    if len(parts) < 6:
        return {}
    timestamp = " ".join(parts[0:3])
    ip = parts[-4] if len(parts) >= 4 else ""
    fields = {
        "timestamp": timestamp,
        "raw": line.strip(),
        "log_source": "linux",
        "ip_address": ip,
        "message": line.strip(),
    }
    return fields


def _parse_apache_line(line: str) -> Dict[str, str]:
    try:
        ip = line.split(" ", 1)[0]
        timestamp_section = line.split("[")[1].split("]")[0]
        parts = line.split("\"")
        request_line = parts[1] if len(parts) > 1 else ""
        remainder = parts[2].strip() if len(parts) > 2 else ""
        status_code = remainder.split()[0] if remainder else ""
        method, url, protocol = (request_line.split() + ["", "", ""])[:3]
    except Exception:
        return {}
    fields = {
        "timestamp": timestamp_section,
        "raw": line.strip(),
        "log_source": "apache",
        "ip_address": ip,
        "request": request_line,
        "status_code": status_code,
        "url": url,
        "method": method,
        "protocol": protocol,
    }
    return fields


def parse_log(file_path: str) -> List[Dict[str, str]]:
    if not os.path.exists(file_path):
        print(f"Log file not found: {file_path}")
        return []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
        lines = [ln for ln in (line.strip() for line in handle.readlines()) if ln]

    log_type = _detect_type(lines)
    parsed: List[Dict[str, str]] = []
    for line in lines:
        if log_type == "windows":
            entry = _parse_windows_line(line)
        elif log_type == "linux":
            entry = _parse_linux_line(line)
        elif log_type == "apache":
            entry = _parse_apache_line(line)
        else:
            entry = {"timestamp": datetime.utcnow().isoformat(), "raw": line, "log_source": "unknown"}
        if entry:
            parsed.append(entry)
    return parsed
