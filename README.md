# Linux User & Security Audit Tool

A comprehensive Bash script that audits Linux user accounts, sudo privileges, password policies, SSH configuration, and common security misconfigurations.

## Features

| Check | Description |
|-------|-------------|
| **System Overview** | Hostname, kernel, distro, uptime, user count |
| **User Account Audit** | Lists all accounts with UID, shell, home directory |
| **UID 0 Detection** | Flags non-root accounts with UID 0 (root-equivalent) |
| **Password Status** | Detects empty passwords, missing expiry, locked accounts |
| **Sudo Privileges** | Parses sudoers + drop-in files, flags NOPASSWD:ALL |
| **Login Shell Audit** | Service accounts with interactive shells |
| **SSH Security** | PermitRootLogin, empty passwords, MaxAuthTries, authorized keys |
| **Password Policy** | login.defs + PAM (pam_pwquality/pam_cracklib) |
| **SUID/SGID Binaries** | Finds unusual setuid/setgid files for privesc risk |
| **World-Writable Files** | Checks /etc and /usr for insecure permissions |
| **Login Activity** | Recent logins, current sessions, failed attempts |
| **Cron Jobs** | Lists scheduled tasks per user (persistence check) |

## Usage

```bash
# Make executable
chmod +x linux_user_audit.sh

# Run (requires root)
sudo ./linux_user_audit.sh

# Save report to file
sudo ./linux_user_audit.sh --report audit_report.txt
```

## Output

The script uses color-coded severity levels:

- **[CRITICAL]** — Immediate security risk (red)
- **[WARNING]** — Potential issue, review recommended (yellow)
- **[OK]** — Check passed (green)
- **[INFO]** — Informational (cyan)

A summary at the end gives overall counts and a final verdict (GOOD / FAIR / ACTION NEEDED).

## Example Output

```
═══════════════════════════════════════════════════════════
  AUDIT SUMMARY
═══════════════════════════════════════════════════════════

  Critical findings: 1
  Warnings:          4
  Passed checks:     8

  Overall: ACTION NEEDED — critical findings require attention

  Audit completed: 2026-11-20 14:30:00 UTC
```

## Requirements

- Linux (Debian/Ubuntu, RHEL/CentOS, Arch, etc.)
- Root privileges (`sudo`)
- Standard coreutils (awk, grep, find)

## Author

Doniyor Sotiboldiyev
