# 🛠️ Unix Server Health Checker (Bash)

> A lightweight, secure, and production-ready Bash script to monitor key system health metrics and log them to standard Unix directories — **no email, no bloat, just reliable monitoring**.

[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)
[![OS](https://img.shields.io/badge/OS-Linux%20%7C%20Unix-blue?logo=linux&logoColor=white)](https://www.kernel.org/)
[![Language](https://img.shields.io/badge/Language-Bash-green?logo=gnu-bash)](https://www.gnu.org/software/bash/)

---

## 📌 Overview

`health-checker.sh` is a robust, zero-dependency Bash script designed to monitor critical system health metrics on Unix/Linux servers. It logs detailed diagnostics to standard Unix locations (`/var/log/health-checker/`) and generates structured JSON reports — **no email, SMS, or external alerts**.

Perfect for:
- System monitoring in production
- Infrastructure auditing
- CI/CD pipeline health checks
- DevOps automation

---

## ✅ Features

- ✅ Monitors CPU load, memory, disk usage, processes, network, and key services
- ✅ Logs to `/var/log/health-checker/` — standard Unix location
- ✅ Daily rotated logs with timestamped filenames
- ✅ Generates structured JSON health reports (ideal for automation)
- ✅ Runs via `cron` or `systemd` — minimal maintenance
- ✅ No external dependencies (only core Bash + `awk`, `grep`, `df`, etc.)
- ✅ Secure file permissions and ownership
- ✅ Compatible with `rsyslog`, `journald`, and `syslog`

---

## 📁 Directory Structure

```
/var/log/health-checker/
├── health-checker.log              # Current daily log
├── health-checker-2025-04-05.log # Archived logs (daily)
├── reports/
│   └── health-report-2025-04-05.json  # Daily JSON health report
└── tmp/
    └── last-check.timestamp          # Last run timestamp
```
> ✅ All logs follow Unix best practices and are compatible with `logrotate`, `rsyslog`, and centralized logging.

---

## 📦 Installation

1. Save the script:

```bash
sudo nano /usr/local/bin/health-checker.sh
```
Paste the full script from the repository. 

2. Make it executable:
```
sudo chmod +x /usr/local/bin/health-checker.sh
```

## 📂 Log Rotation & Cleanup 

     Logs older than 7 days are automatically deleted.
     Daily logs are rotated and archived.
     Use logrotate if you want more control.
     

Optional: logrotate config (/etc/logrotate.d/health-checker) 
```
/var/log/health-checker/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 644 root root
    postrotate
        /bin/systemctl reload rsyslog >/dev/null 2>&1 || true
    endscript
}
```

## 🧪 Testing the Script 
```
# Run manually to test
sudo /usr/local/bin/health-checker.sh

# Check logs
tail -f /var/log/health-checker/health-checker.log

# View JSON report
cat /var/log/health-checker/reports/health-report-*.json
```
## 🛡️ Security & Permissions 

- Runs as root (recommended for full system access)
- Logs are owned by root:root, permissions 644
- No passwords, no network calls — secure by design
- Avoid running as sudo unless necessary
     

🔒 Tip: Use sudo only when needed. Run via cron with root context for best results. 
     
