#!/bin/bash
#
# linux_user_audit.sh — Linux User & Security Audit Tool
# Checks users, sudo privileges, UID policies, password settings,
# and common security misconfigurations.
#
# Usage: sudo ./linux_user_audit.sh [--report FILE]
# Requires root for full audit capability.

set -euo pipefail

RED='\033[0;31m'
YEL='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

REPORT_FILE=""
FINDINGS=0
WARNINGS=0
PASSED=0

usage() {
    echo "Usage: sudo $0 [--report FILE]"
    echo "  --report FILE   Save audit results to FILE (plain text)"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --report) REPORT_FILE="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] Run as root for full audit: sudo $0${RST}"
    exit 1
fi

log_buf=""

out() {
    echo -e "$1"
    log_buf+="$(echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g')"$'\n'
}

finding() {
    out "${RED}[CRITICAL]${RST} $1"
    ((FINDINGS++)) || true
}

warning() {
    out "${YEL}[WARNING]${RST}  $1"
    ((WARNINGS++)) || true
}

passed() {
    out "${GRN}[OK]${RST}       $1"
    ((PASSED++)) || true
}

info() {
    out "${CYN}[INFO]${RST}     $1"
}

section() {
    out ""
    out "${BLD}═══════════════════════════════════════════════════════════${RST}"
    out "${BLD}  $1${RST}"
    out "${BLD}═══════════════════════════════════════════════════════════${RST}"
}

# ─────────────────────────────────────────────
# 1. SYSTEM OVERVIEW
# ─────────────────────────────────────────────
section "1. SYSTEM OVERVIEW"

HOSTNAME=$(hostname)
KERNEL=$(uname -r)
DISTRO=$(cat /etc/os-release 2>/dev/null | grep "^PRETTY_NAME" | cut -d= -f2 | tr -d '"')
UPTIME=$(uptime -p 2>/dev/null || uptime)
TOTAL_USERS=$(awk -F: '{print $1}' /etc/passwd | wc -l)
HUMAN_USERS=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | wc -l)

info "Hostname:      $HOSTNAME"
info "Kernel:        $KERNEL"
info "Distro:        ${DISTRO:-Unknown}"
info "Uptime:        $UPTIME"
info "Total accounts: $TOTAL_USERS  |  Human users (UID>=1000): $HUMAN_USERS"

# ─────────────────────────────────────────────
# 2. USER ACCOUNT AUDIT
# ─────────────────────────────────────────────
section "2. USER ACCOUNT AUDIT"

out "${BLD}  UID    USER             SHELL              HOME${RST}"
out "  ─────  ───────────────  ─────────────────  ────────────────────"
while IFS=: read -r user _ uid _ _ home shell; do
    printf -v line "  %-5s  %-15s  %-17s  %s" "$uid" "$user" "$shell" "$home"
    if [[ $uid -eq 0 && "$user" != "root" ]]; then
        finding "UID 0 account (root-equivalent): $user"
    fi
    out "$line"
done < <(awk -F: '$3 < 1000 || $3 >= 1000 && $3 < 65534' /etc/passwd | sort -t: -k3 -n)

# ─────────────────────────────────────────────
# 3. UID 0 ACCOUNTS (root-equivalent)
# ─────────────────────────────────────────────
section "3. UID 0 ACCOUNTS CHECK"

uid0_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
uid0_count=$(echo "$uid0_users" | wc -w)

if [[ $uid0_count -eq 1 ]]; then
    passed "Only 'root' has UID 0"
else
    finding "$uid0_count accounts with UID 0: $uid0_users"
fi

# ─────────────────────────────────────────────
# 4. EMPTY / NO PASSWORD CHECK
# ─────────────────────────────────────────────
section "4. PASSWORD STATUS AUDIT"

empty_pw=0
locked=0
no_expire=0

while IFS=: read -r user pw_hash _ min max warn inactive expire _rest; do
    if [[ -z "$pw_hash" || "$pw_hash" == " " ]]; then
        finding "EMPTY password: $user"
        ((empty_pw++)) || true
    fi

    if [[ "$pw_hash" == "!" || "$pw_hash" == "!!" || "$pw_hash" == "*" ]]; then
        ((locked++)) || true
    fi

    if [[ "$max" == "99999" || "$max" == "-1" || -z "$max" ]]; then
        uid_num=$(id -u "$user" 2>/dev/null || echo 0)
        if [[ $uid_num -ge 1000 && $uid_num -lt 65534 ]]; then
            warning "No password expiry set for human user: $user (max=$max)"
            ((no_expire++)) || true
        fi
    fi
done < /etc/shadow

if [[ $empty_pw -eq 0 ]]; then
    passed "No accounts with empty passwords"
fi
info "Locked/disabled accounts: $locked"

# ─────────────────────────────────────────────
# 5. SUDO PRIVILEGES AUDIT
# ─────────────────────────────────────────────
section "5. SUDO PRIVILEGES AUDIT"

out "${BLD}  /etc/sudoers entries:${RST}"
if [[ -f /etc/sudoers ]]; then
    while IFS= read -r line; do
        trimmed="${line## }"
        [[ -z "$trimmed" || "$trimmed" == \#* ]] && continue

        out "    $trimmed"

        if echo "$trimmed" | grep -qiE 'NOPASSWD\s*:\s*ALL'; then
            finding "NOPASSWD:ALL found — passwordless root: $trimmed"
        fi

        if echo "$trimmed" | grep -qiE '\(ALL\s*:\s*ALL\)\s+ALL'; then
            user_field=$(echo "$trimmed" | awk '{print $1}')
            if [[ "$user_field" != "root" && "$user_field" != "%sudo" && "$user_field" != "%wheel" && "$user_field" != "%admin" ]]; then
                warning "Full sudo (ALL:ALL) ALL for: $user_field"
            fi
        fi
    done < /etc/sudoers
fi

out ""
out "${BLD}  /etc/sudoers.d/ drop-in files:${RST}"
if [[ -d /etc/sudoers.d ]]; then
    for f in /etc/sudoers.d/*; do
        [[ -f "$f" ]] || continue
        info "  File: $f"
        while IFS= read -r line; do
            trimmed="${line## }"
            [[ -z "$trimmed" || "$trimmed" == \#* ]] && continue
            out "    $trimmed"

            if echo "$trimmed" | grep -qiE 'NOPASSWD\s*:\s*ALL'; then
                finding "NOPASSWD:ALL in $f: $trimmed"
            fi
        done < "$f"
    done
else
    info "  /etc/sudoers.d/ does not exist"
fi

out ""
out "${BLD}  Users in sudo/wheel/admin groups:${RST}"
for grp in sudo wheel admin; do
    members=$(getent group "$grp" 2>/dev/null | cut -d: -f4)
    if [[ -n "$members" ]]; then
        info "  Group '$grp': $members"
    fi
done

# ─────────────────────────────────────────────
# 6. LOGIN SHELL AUDIT
# ─────────────────────────────────────────────
section "6. LOGIN SHELL AUDIT"

nologin_shells="/usr/sbin/nologin /sbin/nologin /bin/false"

while IFS=: read -r user _ uid _ _ _ shell; do
    [[ $uid -lt 1000 ]] && continue
    [[ $uid -ge 65534 ]] && continue

    is_nologin=0
    for ns in $nologin_shells; do
        [[ "$shell" == "$ns" ]] && is_nologin=1 && break
    done

    if [[ $is_nologin -eq 0 ]]; then
        if [[ ! -x "$shell" ]]; then
            warning "User '$user' has non-existent/non-executable shell: $shell"
        else
            info "User '$user' → $shell"
        fi
    fi
done < /etc/passwd

svc_with_shell=0
while IFS=: read -r user _ uid _ _ _ shell; do
    [[ $uid -ge 1000 ]] && continue
    [[ $uid -eq 0 ]] && continue

    is_nologin=0
    for ns in $nologin_shells; do
        [[ "$shell" == "$ns" ]] && is_nologin=1 && break
    done

    if [[ $is_nologin -eq 0 && "$shell" != "/bin/sync" && "$shell" != "/usr/bin/false" ]]; then
        warning "Service account '$user' (UID $uid) has login shell: $shell"
        ((svc_with_shell++)) || true
    fi
done < /etc/passwd

if [[ $svc_with_shell -eq 0 ]]; then
    passed "No service accounts with interactive login shells"
fi

# ─────────────────────────────────────────────
# 7. SSH CONFIGURATION CHECK
# ─────────────────────────────────────────────
section "7. SSH SECURITY CHECK"

SSHD_CONF="/etc/ssh/sshd_config"
if [[ -f "$SSHD_CONF" ]]; then
    permit_root=$(grep -i "^PermitRootLogin" "$SSHD_CONF" 2>/dev/null | awk '{print $2}' | tail -1)
    pw_auth=$(grep -i "^PasswordAuthentication" "$SSHD_CONF" 2>/dev/null | awk '{print $2}' | tail -1)
    permit_empty=$(grep -i "^PermitEmptyPasswords" "$SSHD_CONF" 2>/dev/null | awk '{print $2}' | tail -1)
    max_auth=$(grep -i "^MaxAuthTries" "$SSHD_CONF" 2>/dev/null | awk '{print $2}' | tail -1)
    proto=$(grep -i "^Protocol" "$SSHD_CONF" 2>/dev/null | awk '{print $2}' | tail -1)

    if [[ "${permit_root,,}" == "yes" ]]; then
        finding "SSH PermitRootLogin is YES"
    elif [[ "${permit_root,,}" == "no" || "${permit_root,,}" == "prohibit-password" ]]; then
        passed "SSH PermitRootLogin: ${permit_root}"
    else
        warning "SSH PermitRootLogin not explicitly set (default may allow root)"
    fi

    if [[ "${permit_empty,,}" == "yes" ]]; then
        finding "SSH PermitEmptyPasswords is YES"
    else
        passed "SSH PermitEmptyPasswords: ${permit_empty:-no (default)}"
    fi

    if [[ -n "$pw_auth" ]]; then
        info "SSH PasswordAuthentication: $pw_auth"
    fi

    if [[ -n "$max_auth" ]]; then
        if [[ "$max_auth" -gt 6 ]]; then
            warning "SSH MaxAuthTries is high: $max_auth (recommended: 3-6)"
        else
            passed "SSH MaxAuthTries: $max_auth"
        fi
    fi

    authorized_keys_found=0
    for homedir in /home/*/; do
        u=$(basename "$homedir")
        ak="$homedir.ssh/authorized_keys"
        if [[ -f "$ak" ]]; then
            key_count=$(grep -c "^ssh-" "$ak" 2>/dev/null || echo 0)
            info "User '$u' has $key_count SSH authorized key(s)"
            ((authorized_keys_found++)) || true
        fi
    done
    if [[ $authorized_keys_found -eq 0 ]]; then
        info "No authorized_keys files found in /home/*/"
    fi
else
    info "sshd_config not found — SSH may not be installed"
fi

# ─────────────────────────────────────────────
# 8. PASSWORD POLICY (login.defs + PAM)
# ─────────────────────────────────────────────
section "8. PASSWORD POLICY"

if [[ -f /etc/login.defs ]]; then
    pass_max=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    pass_min=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    pass_len=$(grep "^PASS_MIN_LEN" /etc/login.defs 2>/dev/null | awk '{print $2}')
    pass_warn=$(grep "^PASS_WARN_AGE" /etc/login.defs 2>/dev/null | awk '{print $2}')
    uid_min=$(grep "^UID_MIN" /etc/login.defs 2>/dev/null | awk '{print $2}')
    uid_max=$(grep "^UID_MAX" /etc/login.defs 2>/dev/null | awk '{print $2}')

    info "PASS_MAX_DAYS: ${pass_max:-not set}"
    info "PASS_MIN_DAYS: ${pass_min:-not set}"
    info "PASS_MIN_LEN:  ${pass_len:-not set}"
    info "PASS_WARN_AGE: ${pass_warn:-not set}"
    info "UID_MIN:       ${uid_min:-not set}"
    info "UID_MAX:       ${uid_max:-not set}"

    if [[ "${pass_max:-99999}" == "99999" ]]; then
        warning "PASS_MAX_DAYS=99999 — passwords never expire by default"
    fi
    if [[ "${pass_len:-0}" -lt 8 ]] 2>/dev/null; then
        warning "PASS_MIN_LEN < 8 (current: ${pass_len:-not set})"
    fi
else
    warning "/etc/login.defs not found"
fi

out ""
out "${BLD}  PAM password quality:${RST}"
pam_pwquality=0
for pam_file in /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    if [[ -f "$pam_file" ]]; then
        if grep -q "pam_pwquality" "$pam_file" 2>/dev/null; then
            info "pam_pwquality enabled in $pam_file"
            grep "pam_pwquality" "$pam_file" | while IFS= read -r l; do
                out "    $l"
            done
            pam_pwquality=1
        fi
        if grep -q "pam_cracklib" "$pam_file" 2>/dev/null; then
            info "pam_cracklib enabled in $pam_file"
            pam_pwquality=1
        fi
    fi
done
if [[ $pam_pwquality -eq 0 ]]; then
    warning "No password complexity module (pam_pwquality/pam_cracklib) detected"
fi

# ─────────────────────────────────────────────
# 9. SUID/SGID BINARIES
# ─────────────────────────────────────────────
section "9. SUID/SGID BINARIES (potential privilege escalation)"

known_suid="/usr/bin/sudo /usr/bin/su /usr/bin/passwd /usr/bin/chsh /usr/bin/chfn /usr/bin/newgrp /usr/bin/gpasswd /usr/bin/mount /usr/bin/umount /usr/bin/fusermount /usr/bin/fusermount3 /usr/bin/pkexec /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/lib/openssh/ssh-keysign /usr/lib/snapd/snap-confine /usr/sbin/pppd /usr/bin/crontab"

suspicious=0
while IFS= read -r suid_bin; do
    is_known=0
    for kb in $known_suid; do
        [[ "$suid_bin" == "$kb" ]] && is_known=1 && break
    done
    if [[ $is_known -eq 0 ]]; then
        warning "Unusual SUID/SGID binary: $suid_bin"
        ((suspicious++)) || true
    fi
done < <(find / -perm /6000 -type f 2>/dev/null | sort)

if [[ $suspicious -eq 0 ]]; then
    passed "No unusual SUID/SGID binaries found"
fi

# ─────────────────────────────────────────────
# 10. WORLD-WRITABLE FILES IN SENSITIVE DIRS
# ─────────────────────────────────────────────
section "10. WORLD-WRITABLE SENSITIVE FILES"

ww_found=0
while IFS= read -r ww_file; do
    finding "World-writable: $ww_file"
    ((ww_found++)) || true
done < <(find /etc /usr -type f -perm -o+w 2>/dev/null | head -20)

if [[ $ww_found -eq 0 ]]; then
    passed "No world-writable files in /etc or /usr"
fi

# ─────────────────────────────────────────────
# 11. RECENTLY LOGGED-IN USERS
# ─────────────────────────────────────────────
section "11. RECENT LOGIN ACTIVITY"

out "${BLD}  Last 10 logins:${RST}"
last -10 -w 2>/dev/null | while IFS= read -r line; do
    [[ -n "$line" ]] && out "    $line"
done

out ""
out "${BLD}  Currently logged-in users:${RST}"
who 2>/dev/null | while IFS= read -r line; do
    out "    $line"
done

out ""
out "${BLD}  Failed login attempts (last 10):${RST}"
if [[ -f /var/log/auth.log ]]; then
    grep "Failed password" /var/log/auth.log 2>/dev/null | tail -10 | while IFS= read -r line; do
        out "    $line"
    done
elif [[ -f /var/log/secure ]]; then
    grep "Failed password" /var/log/secure 2>/dev/null | tail -10 | while IFS= read -r line; do
        out "    $line"
    done
else
    info "  No auth log found (journalctl may be needed)"
fi

# ─────────────────────────────────────────────
# 12. CRON JOBS (potential persistence)
# ─────────────────────────────────────────────
section "12. CRON JOBS & SCHEDULED TASKS"

for cron_dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [[ -d "$cron_dir" ]]; then
        file_count=$(ls -1 "$cron_dir" 2>/dev/null | wc -l)
        info "$cron_dir: $file_count file(s)"
    fi
done

out ""
out "${BLD}  User crontabs:${RST}"
for user_home in /home/*/; do
    u=$(basename "$user_home")
    crontab_out=$(crontab -u "$u" -l 2>/dev/null | grep -v "^#" | grep -v "^$") || true
    if [[ -n "$crontab_out" ]]; then
        info "  Crontab for '$u':"
        echo "$crontab_out" | while IFS= read -r line; do
            out "    $line"
        done
    fi
done
root_cron=$(crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$") || true
if [[ -n "$root_cron" ]]; then
    info "  Crontab for 'root':"
    echo "$root_cron" | while IFS= read -r line; do
        out "    $line"
    done
fi

# ─────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────
section "AUDIT SUMMARY"

out ""
out "  ${RED}Critical findings: $FINDINGS${RST}"
out "  ${YEL}Warnings:          $WARNINGS${RST}"
out "  ${GRN}Passed checks:     $PASSED${RST}"
out ""

TOTAL=$((FINDINGS + WARNINGS + PASSED))
if [[ $FINDINGS -eq 0 && $WARNINGS -le 3 ]]; then
    out "  ${GRN}${BLD}Overall: GOOD — system appears well-configured${RST}"
elif [[ $FINDINGS -eq 0 ]]; then
    out "  ${YEL}${BLD}Overall: FAIR — no critical issues but several warnings${RST}"
else
    out "  ${RED}${BLD}Overall: ACTION NEEDED — critical findings require attention${RST}"
fi

out ""
out "  Audit completed: $(date '+%Y-%m-%d %H:%M:%S %Z')"
out "  Audited by: linux_user_audit.sh v1.0"

if [[ -n "$REPORT_FILE" ]]; then
    echo "$log_buf" | sed 's/\x1b\[[0-9;]*m//g' > "$REPORT_FILE"
    echo ""
    echo -e "${GRN}[+] Report saved to: $REPORT_FILE${RST}"
fi
