# ============================================
# Adaptive Cyber Resilience and Automated
# Threat Neutralization System (ACRTS)
# Team  : Jahnavi Singh, Darsh Bindra,
#          Aayushi Malik, Mohini
# Repo  : https://github.com/jahnavi-37
# Version: 1.0
# ============================================

import random
import time
from datetime import datetime, timedelta
from pathlib import Path

LOG_BASE = Path("sample_logs")
APACHE_LOG = LOG_BASE / "apache_access.log"
AUTH_LOG = LOG_BASE / "auth.log"
WINDOWS_LOG = LOG_BASE / "windows_events.log"
ATTACK_IP = "45.33.32.156"


def slow_print(lines: list[str], delay: float = 0.5) -> None:
    for line in lines:
        print(line)
        time.sleep(delay)


def write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for line in lines:
            handle.write(line + "\n")


def phase1_recon(base_time: datetime) -> None:
    print("[PHASE 1] RECONAISSANCE WHISPER")
    endpoints = ["/index.php", "/admin.php", "/server-status", "/wp-login.php", "/robots.txt", "/dev/", "/logs/", "/shadow/"]
    lines: list[str] = []
    for i, path in enumerate(endpoints):
        stamp = (base_time + timedelta(minutes=2 * i)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(f"{ATTACK_IP} - - [{stamp}] \"GET {path} HTTP/1.1\" 200 {random.choice([180, 220, 512, 980])}")

    slow_print(["scanning HTTP surface...", "indexing hidden directories...", "enumeration complete"], delay=0.5)
    write_lines(APACHE_LOG, lines)
    print("Recon mapped endpoints across apache logs.")


def phase2_bruteforce(base_time: datetime) -> None:
    print("[PHASE 2] SSH BRUTE FORCE")
    users = ["root", "admin", "dev", "ubuntu", "guest", "oracle", "postgres", "backup"]
    lines: list[str] = []
    for i, user in enumerate(users):
        stamp = (base_time + timedelta(seconds=i + 1)).strftime("%b %d %H:%M:%S")
        port = random.choice([22, 2222, 2200])
        lines.append(f"{stamp} server sshd[2310]: Failed password for {user} from {ATTACK_IP} port {port} ssh2")
    slow_print([f"{ATTACK_IP} attempting credentials: {u}" for u in users], delay=0.5)
    write_lines(AUTH_LOG, lines)
    print("SSH brute force recorded in auth.log")


def phase3_sql_injection(base_time: datetime) -> None:
    print("[PHASE 3] SQL INJECTION BLAST")
    payloads = [
        "'/login.php?user=admin' OR 1=1--",
        "'/index.php?id=4 UNION SELECT * FROM users--",
        "'/products.php?id=5; DROP TABLE payments--",
        "'/search.php?q=' OR '1'='1",
        "'/profile.php?user=admin' UNION SELECT password FROM users--",
    ]
    lines: list[str] = []
    for i, payload in enumerate(payloads):
        stamp = (base_time + timedelta(seconds=2 * i)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(f"{ATTACK_IP} - - [{stamp}] \"GET {payload} HTTP/1.1\" 200 520")
    slow_print([f"injecting payload -> {p}" for p in payloads], delay=0.5)
    write_lines(APACHE_LOG, lines)
    print("Injection traces appended to apache_access.log")


def phase4_priv_esc(base_time: datetime) -> None:
    print("[PHASE 4] PRIVILEGE ESCALATION")
    events = [
        ("cmd.exe", "powershell.exe"),
        ("net.exe", "cmd.exe"),
        ("powershell.exe", "winword.exe"),
    ]
    lines: list[str] = []
    for i, (proc, parent) in enumerate(events):
        stamp = (base_time + timedelta(seconds=3 * i)).strftime("%Y-%m-%d %H:%M:%S")
        lines.append(
            f"{stamp} EventID=4688 ProcessName={proc} ParentProcess={parent} SourceIP={ATTACK_IP}"
        )
    slow_print([f"{p[0]} spawned via {p[1]}" for p in events], delay=0.5)
    write_lines(WINDOWS_LOG, lines)
    print("Process lineage written to windows_events.log")


def main() -> None:
    print("============================================")
    print("ACRTS - LIVE ATTACK SIMULATION")
    print(f"Simulating adversary from IP: {ATTACK_IP}")
    print("============================================")

    base = datetime.utcnow()
    time.sleep(0.75)
    print(f"Inbound connection from {ATTACK_IP} deployed")
    time.sleep(0.75)

    phase1_recon(base)
    time.sleep(2)
    phase2_bruteforce(base + timedelta(minutes=5))
    time.sleep(2)
    phase3_sql_injection(base + timedelta(minutes=7))
    time.sleep(2)
    phase4_priv_esc(base + timedelta(minutes=9))

    print("============================================")
    print("SIMULATION COMPLETE")
    print("All attack phases written to sample_logs/")
    print("Run: python3 main.py  (to detect)")
    print("Run: python3 -m streamlit run dashboard.py  (to view SOC)")
    print("============================================")


if __name__ == "__main__":
    main()
