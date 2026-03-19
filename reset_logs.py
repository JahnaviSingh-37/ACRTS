# ============================================
# Adaptive Cyber Resilience and Automated
# Threat Neutralization System (ACRTS)
# Team  : Jahnavi Singh, Darsh Bindra,
#          Aayushi Malik, Mohini
# Repo  : https://github.com/jahnavi-37
# Version: 1.0
# ============================================

from pathlib import Path

BASE_DIR = Path("sample_logs")
APACHE_LOG = BASE_DIR / "apache_access.log"
AUTH_LOG = BASE_DIR / "auth.log"
WINDOWS_LOG = BASE_DIR / "windows_events.log"

APACHE_BASE = """192.168.1.50 - - [15/Jan/2024:10:22:33 +0000] \"GET /index.php?id=1 OR 1=1-- HTTP/1.1\" 200 512
192.168.1.50 - - [15/Jan/2024:10:22:34 +0000] \"GET /login.php?user=admin' UNION SELECT * FROM users-- HTTP/1.1\" 200 512
10.0.0.99 - - [15/Jan/2024:11:05:10 +0000] \"GET /page?id=1; DROP TABLE users-- HTTP/1.1\" 200 512
172.16.0.77 - - [15/Jan/2024:11:30:45 +0000] \"GET /scan?port=80 HTTP/1.1\" 200 100
172.16.0.77 - - [15/Jan/2024:11:30:46 +0000] \"GET /scan?port=443 HTTP/1.1\" 200 100
172.16.0.77 - - [15/Jan/2024:11:30:47 +0000] \"GET /scan?port=8080 HTTP/1.1\" 200 100
172.16.0.77 - - [15/Jan/2024:11:30:48 +0000] \"GET /scan?port=21 HTTP/1.1\" 200 100
172.16.0.77 - - [15/Jan/2024:11:30:49 +0000] \"GET /scan?port=22 HTTP/1.1\" 200 100
172.16.0.77 - - [15/Jan/2024:11:30:50 +0000] \"GET /scan?port=25 HTTP/1.1\" 200 100
172.16.0.77 - - [15/Jan/2024:11:30:51 +0000] \"GET /scan?port=53 HTTP/1.1\" 200 100
172.16.0.77 - - [15/Jan/2024:11:30:52 +0000] \"GET /scan?port=110 HTTP/1.1\" 200 100
172.16.0.77 - - [15/Jan/2024:11:30:53 +0000] \"GET /scan?port=143 HTTP/1.1\" 200 100
172.16.0.77 - - [15/Jan/2024:11:30:54 +0000] \"GET /scan?port=389 HTTP/1.1\" 200 100
172.16.0.77 - - [15/Jan/2024:11:30:55 +0000] \"GET /scan?port=993 HTTP/1.1\" 200 100
172.16.0.77 - - [15/Jan/2024:11:30:56 +0000] \"GET /scan?port=995 HTTP/1.1\" 200 100
192.168.1.90 - - [15/Jan/2024:12:00:01 +0000] \"GET /index.php?id=5 AND 1=1 HTTP/1.1\" 200 512
192.168.1.90 - - [15/Jan/2024:12:00:05 +0000] \"GET /search.php?q=' OR '1'='1 HTTP/1.1\" 200 520
192.168.1.90 - - [15/Jan/2024:12:00:10 +0000] \"GET /user.php?name=admin' OR 'a'='a HTTP/1.1\" 200 520
203.0.113.10 - - [15/Jan/2024:12:15:15 +0000] \"GET /login.php?user=admin' OR 1=1-- HTTP/1.1\" 200 530
203.0.113.10 - - [15/Jan/2024:12:15:20 +0000] \"GET /products.php?id=2 UNION SELECT creditcard FROM payments-- HTTP/1.1\" 200 540
198.51.100.25 - - [15/Jan/2024:12:45:30 +0000] \"GET /catalog.php?id=10 HTTP/1.1\" 200 620
198.51.100.25 - - [15/Jan/2024:12:45:35 +0000] \"POST /login HTTP/1.1\" 401 200
198.51.100.25 - - [15/Jan/2024:12:45:40 +0000] \"POST /login HTTP/1.1\" 401 200
198.51.100.25 - - [15/Jan/2024:12:45:45 +0000] \"POST /login HTTP/1.1\" 200 200
192.0.2.77 - - [15/Jan/2024:13:05:05 +0000] \"GET /index.php?id=7; DROP TABLE sessions-- HTTP/1.1\" 200 512
192.0.2.77 - - [15/Jan/2024:13:05:10 +0000] \"GET /profile.php?user=1 UNION SELECT password FROM users-- HTTP/1.1\" 200 512
192.0.2.77 - - [15/Jan/2024:13:05:15 +0000] \"GET /search.php?q=%27%20OR%20%271%27=%271 HTTP/1.1\" 200 500
10.0.0.23 - - [15/Jan/2024:13:30:00 +0000] \"GET /health HTTP/1.1\" 200 20
10.0.0.23 - - [15/Jan/2024:13:31:00 +0000] \"GET /metrics HTTP/1.1\" 200 25
172.16.0.99 - - [15/Jan/2024:14:00:00 +0000] \"GET /admin.php?id=1; DROP TABLE audit-- HTTP/1.1\" 200 520
172.16.0.99 - - [15/Jan/2024:14:00:02 +0000] \"GET /admin.php?id=2 UNION SELECT * FROM admin-- HTTP/1.1\" 200 520
172.16.0.99 - - [15/Jan/2024:14:00:04 +0000] \"GET /admin.php?id=3 OR 1=1 HTTP/1.1\" 200 520
172.16.0.99 - - [15/Jan/2024:14:00:06 +0000] \"GET /admin.php?id=4 AND 'a'='a HTTP/1.1\" 200 520
172.16.0.99 - - [15/Jan/2024:14:00:08 +0000] \"GET /admin.php?id=5; DROP TABLE logs-- HTTP/1.1\" 200 520
172.16.0.50 - - [15/Jan/2024:15:15:15 +0000] \"GET /scan?port=25 HTTP/1.1\" 200 100
172.16.0.50 - - [15/Jan/2024:15:15:16 +0000] \"GET /scan?port=53 HTTP/1.1\" 200 100
172.16.0.50 - - [15/Jan/2024:15:15:17 +0000] \"GET /scan?port=80 HTTP/1.1\" 200 100
172.16.0.50 - - [15/Jan/2024:15:15:18 +0000] \"GET /scan?port=110 HTTP/1.1\" 200 100
172.16.0.50 - - [15/Jan/2024:15:15:19 +0000] \"GET /scan?port=143 HTTP/1.1\" 200 100
172.16.0.50 - - [15/Jan/2024:15:15:20 +0000] \"GET /scan?port=443 HTTP/1.1\" 200 100
203.0.113.200 - - [16/Jan/2024:08:00:00 +0000] \"GET /about HTTP/1.1\" 200 256
203.0.113.200 - - [16/Jan/2024:08:12:00 +0000] \"GET /products HTTP/1.1\" 200 260
203.0.113.200 - - [16/Jan/2024:08:25:00 +0000] \"GET /blog HTTP/1.1\" 200 240
203.0.113.200 - - [16/Jan/2024:08:37:00 +0000] \"GET /pricing HTTP/1.1\" 200 250
203.0.113.200 - - [16/Jan/2024:08:50:00 +0000] \"GET /careers HTTP/1.1\" 200 255
203.0.113.200 - - [16/Jan/2024:09:05:00 +0000] \"GET /status HTTP/1.1\" 200 200
203.0.113.200 - - [16/Jan/2024:09:18:00 +0000] \"GET /contact HTTP/1.1\" 200 230
203.0.113.200 - - [16/Jan/2024:09:30:00 +0000] \"GET /partners HTTP/1.1\" 200 240
203.0.113.200 - - [16/Jan/2024:09:45:00 +0000] \"GET /api/docs HTTP/1.1\" 200 420
203.0.113.200 - - [16/Jan/2024:10:00:00 +0000] \"GET /api/v1/users HTTP/1.1\" 200 410
203.0.113.200 - - [16/Jan/2024:10:12:00 +0000] \"GET /api/v1/payments HTTP/1.1\" 200 405
203.0.113.200 - - [16/Jan/2024:10:25:00 +0000] \"GET /api/v1/orders HTTP/1.1\" 200 415
203.0.113.200 - - [16/Jan/2024:10:40:00 +0000] \"GET /search?q=summer HTTP/1.1\" 200 320
203.0.113.200 - - [16/Jan/2024:10:55:00 +0000] \"GET /search?q=winter HTTP/1.1\" 200 325
203.0.113.200 - - [16/Jan/2024:11:10:00 +0000] \"GET /faq HTTP/1.1\" 200 210
203.0.113.200 - - [16/Jan/2024:11:25:00 +0000] \"GET /legal/terms HTTP/1.1\" 200 215
203.0.113.200 - - [16/Jan/2024:11:40:00 +0000] \"GET /legal/privacy HTTP/1.1\" 200 215
203.0.113.200 - - [16/Jan/2024:11:55:00 +0000] \"GET /sso/login HTTP/1.1\" 200 280
203.0.113.200 - - [16/Jan/2024:12:10:00 +0000] \"GET /downloads/client HTTP/1.1\" 200 285
203.0.113.200 - - [16/Jan/2024:12:15:00 +0000] \"GET /changelog HTTP/1.1\" 200 250
"""

AUTH_BASE = """Jan 15 02:13:45 server sshd[1234]: Failed password for root from 192.168.1.200 port 22 ssh2
Jan 15 02:13:46 server sshd[1234]: Failed password for root from 192.168.1.200 port 22 ssh2
Jan 15 02:13:47 server sshd[1234]: Failed password for admin from 192.168.1.200 port 22 ssh2
Jan 15 03:15:22 server sshd[1235]: Accepted password for deploy from 10.0.0.1 port 22 ssh2
Jan 15 03:45:10 server sshd[1236]: Failed password for root from 172.16.0.50 port 22 ssh2
Jan 15 03:45:11 server sshd[1236]: Failed password for root from 172.16.0.50 port 22 ssh2
Jan 15 03:45:12 server sshd[1236]: Failed password for root from 172.16.0.50 port 22 ssh2
Jan 15 03:45:13 server sshd[1236]: Failed password for root from 172.16.0.50 port 22 ssh2
Jan 15 03:45:14 server sshd[1236]: Failed password for root from 172.16.0.50 port 22 ssh2
Jan 15 04:10:01 server sshd[1240]: Failed password for invalid user test from 203.0.113.10 port 22 ssh2
Jan 15 04:10:03 server sshd[1240]: Failed password for invalid user test from 203.0.113.10 port 22 ssh2
Jan 15 04:10:05 server sshd[1240]: Failed password for invalid user test from 203.0.113.10 port 22 ssh2
Jan 15 04:10:07 server sshd[1240]: Failed password for invalid user test from 203.0.113.10 port 22 ssh2
Jan 15 04:10:09 server sshd[1240]: Failed password for invalid user test from 203.0.113.10 port 22 ssh2
Jan 15 05:00:12 server sshd[1250]: Accepted password for student from 192.168.1.55 port 22 ssh2
Jan 15 05:10:30 server sshd[1255]: Failed password for root from 198.51.100.25 port 22 ssh2
Jan 15 05:10:32 server sshd[1255]: Failed password for root from 198.51.100.25 port 22 ssh2
Jan 15 05:10:34 server sshd[1255]: Failed password for root from 198.51.100.25 port 22 ssh2
Jan 15 05:10:36 server sshd[1255]: Failed password for root from 198.51.100.25 port 22 ssh2
Jan 15 05:10:38 server sshd[1255]: Failed password for root from 198.51.100.25 port 22 ssh2
Jan 15 06:25:45 server sshd[1260]: Failed password for admin from 203.0.113.44 port 22 ssh2
Jan 15 06:25:47 server sshd[1260]: Failed password for admin from 203.0.113.44 port 22 ssh2
Jan 15 06:25:49 server sshd[1260]: Failed password for admin from 203.0.113.44 port 22 ssh2
Jan 15 06:25:51 server sshd[1260]: Failed password for admin from 203.0.113.44 port 22 ssh2
Jan 15 06:25:53 server sshd[1260]: Failed password for admin from 203.0.113.44 port 22 ssh2
Jan 15 07:15:10 server sshd[1265]: Accepted password for dev from 10.0.0.23 port 22 ssh2
Jan 15 08:00:00 server sshd[1270]: Failed password for root from 192.0.2.77 port 22 ssh2
Jan 15 08:00:02 server sshd[1270]: Failed password for root from 192.0.2.77 port 22 ssh2
Jan 15 08:00:04 server sshd[1270]: Failed password for root from 192.0.2.77 port 22 ssh2
Jan 15 08:00:06 server sshd[1270]: Failed password for root from 192.0.2.77 port 22 ssh2
Jan 15 08:00:08 server sshd[1270]: Failed password for root from 192.0.2.77 port 22 ssh2
Jan 15 09:12:10 server sshd[1280]: Failed password for root from 198.51.100.99 port 22 ssh2
Jan 15 09:12:12 server sshd[1280]: Failed password for root from 198.51.100.99 port 22 ssh2
Jan 15 09:12:14 server sshd[1280]: Failed password for root from 198.51.100.99 port 22 ssh2
Jan 15 09:12:16 server sshd[1280]: Failed password for root from 198.51.100.99 port 22 ssh2
Jan 15 09:12:18 server sshd[1280]: Failed password for root from 198.51.100.99 port 22 ssh2
Jan 15 10:45:30 server sshd[1290]: Accepted password for qa from 172.16.0.99 port 22 ssh2
"""

WINDOWS_BASE = """2024-01-15 02:13:45 EventID=4625 SourceIP=192.168.1.105 User=Administrator Status=FailedLogin LogonType=3
2024-01-15 02:13:46 EventID=4625 SourceIP=192.168.1.105 User=Administrator Status=FailedLogin LogonType=3
2024-01-15 02:13:47 EventID=4625 SourceIP=192.168.1.105 User=Administrator Status=FailedLogin LogonType=3
2024-01-15 02:13:48 EventID=4625 SourceIP=192.168.1.105 User=Administrator Status=FailedLogin LogonType=3
2024-01-15 02:13:49 EventID=4625 SourceIP=192.168.1.105 User=Administrator Status=FailedLogin LogonType=3
2024-01-15 02:13:50 EventID=4625 SourceIP=192.168.1.105 User=Administrator Status=FailedLogin LogonType=3
2024-01-15 03:22:10 EventID=4624 SourceIP=10.0.0.55 User=admin Status=Success LogonType=10
2024-01-15 03:22:15 EventID=4688 ProcessName=cmd.exe ParentProcess=powershell.exe SourceIP=10.0.0.55
2024-01-15 04:10:33 EventID=4625 SourceIP=172.16.0.200 User=root Status=FailedLogin LogonType=3
2024-01-15 04:10:34 EventID=4625 SourceIP=172.16.0.200 User=root Status=FailedLogin LogonType=3
2024-01-15 04:10:35 EventID=4625 SourceIP=172.16.0.200 User=root Status=FailedLogin LogonType=3
2024-01-15 04:10:36 EventID=4625 SourceIP=172.16.0.200 User=root Status=FailedLogin LogonType=3
2024-01-15 04:10:37 EventID=4625 SourceIP=172.16.0.200 User=root Status=FailedLogin LogonType=3
2024-01-15 04:10:38 EventID=4625 SourceIP=172.16.0.200 User=root Status=FailedLogin LogonType=3
2024-01-15 05:05:12 EventID=4624 SourceIP=203.0.113.10 User=helpdesk Status=Success LogonType=10
2024-01-15 05:05:20 EventID=4688 ProcessName=powershell.exe ParentProcess=explorer.exe SourceIP=203.0.113.10
2024-01-15 05:05:24 EventID=4688 ProcessName=cmd.exe ParentProcess=powershell.exe SourceIP=203.0.113.10
2024-01-15 06:22:45 EventID=4625 SourceIP=198.51.100.25 User=Administrator Status=FailedLogin LogonType=3
2024-01-15 06:23:00 EventID=4625 SourceIP=198.51.100.25 User=Administrator Status=FailedLogin LogonType=3
2024-01-15 06:23:15 EventID=4625 SourceIP=198.51.100.25 User=Administrator Status=FailedLogin LogonType=3
2024-01-15 06:23:30 EventID=4625 SourceIP=198.51.100.25 User=Administrator Status=FailedLogin LogonType=3
2024-01-15 06:23:45 EventID=4625 SourceIP=198.51.100.25 User=Administrator Status=FailedLogin LogonType=3
2024-01-15 07:10:10 EventID=4688 ProcessName=certutil.exe ParentProcess=cmd.exe SourceIP=10.0.0.88
2024-01-15 07:11:11 EventID=4624 SourceIP=10.0.0.88 User=remote Status=Success LogonType=10
2024-01-15 07:11:15 EventID=4688 ProcessName=powershell.exe ParentProcess=winword.exe SourceIP=10.0.0.88
2024-01-15 08:00:00 EventID=4625 SourceIP=192.0.2.77 User=service Status=FailedLogin LogonType=3
2024-01-15 08:00:10 EventID=4625 SourceIP=192.0.2.77 User=service Status=FailedLogin LogonType=3
2024-01-15 08:00:20 EventID=4625 SourceIP=192.0.2.77 User=service Status=FailedLogin LogonType=3
2024-01-15 08:00:30 EventID=4625 SourceIP=192.0.2.77 User=service Status=FailedLogin LogonType=3
2024-01-15 08:00:40 EventID=4625 SourceIP=192.0.2.77 User=service Status=FailedLogin LogonType=3
2024-01-15 09:30:10 EventID=4688 ProcessName=cmd.exe ParentProcess=powershell.exe SourceIP=198.51.100.25
2024-01-15 10:15:00 EventID=4624 SourceIP=10.0.0.23 User=analyst Status=Success LogonType=2
2024-01-15 10:20:00 EventID=4688 ProcessName=wscript.exe ParentProcess=cmd.exe SourceIP=10.0.0.23
2024-01-15 11:45:30 EventID=4625 SourceIP=203.0.113.44 User=admin Status=FailedLogin LogonType=3
2024-01-15 11:45:40 EventID=4625 SourceIP=203.0.113.44 User=admin Status=FailedLogin LogonType=3
2024-01-15 11:45:50 EventID=4625 SourceIP=203.0.113.44 User=admin Status=FailedLogin LogonType=3
2024-01-15 11:46:00 EventID=4625 SourceIP=203.0.113.44 User=admin Status=FailedLogin LogonType=3
2024-01-15 11:46:10 EventID=4625 SourceIP=203.0.113.44 User=admin Status=FailedLogin LogonType=3
2024-01-15 12:15:15 EventID=4688 ProcessName=cmd.exe ParentProcess=powershell.exe SourceIP=203.0.113.10
2024-01-15 13:05:05 EventID=4624 SourceIP=172.16.0.99 User=test Status=Success LogonType=10
2024-01-15 13:05:07 EventID=4688 ProcessName=cmd.exe ParentProcess=powershell.exe SourceIP=172.16.0.99
"""


def reset_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write(content)


def main() -> None:
    reset_file(APACHE_LOG, APACHE_BASE)
    reset_file(AUTH_LOG, AUTH_BASE)
    reset_file(WINDOWS_LOG, WINDOWS_BASE)
    print("Logs reset successfully")


if __name__ == "__main__":
    main()
