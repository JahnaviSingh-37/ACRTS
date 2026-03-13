# ============================================
# Adaptive Cyber Resilience and Automated
# Threat Neutralization System (ACRTS)
# Team  : Jahnavi Singh, Darsh Bindra,
#          Aayushi Malik, Mohini
# Repo  : https://github.com/jahnavi-37
# Version: 1.0
# ============================================

DEMO_MODE = True
EMAIL_SENDER = "your_email@gmail.com"
EMAIL_PASSWORD = "your_app_password"
EMAIL_RECEIVER = "alert_receiver@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
ALERT_ON_SEVERITY = ["HIGH", "CRITICAL"]
DB_PATH = "acrts.db"
WINDOWS_LOG = "sample_logs/windows_events.log"
LINUX_LOG = "sample_logs/auth.log"
APACHE_LOG = "sample_logs/apache_access.log"
BRUTE_FORCE_THRESHOLD = 5
PORT_SCAN_THRESHOLD = 10
