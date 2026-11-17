#!/usr/bin/env bash
#
# audit-linux-hardening.sh
# Linux Hardening Auditor — Module 2 (Windows/Linux Hardening Auditor)
#
# Audits a Linux host against a CIS-style hardening baseline and produces
# a scored, severity-ranked HTML report a non-security person can act on,
# plus a machine-readable JSON file for pipelines / diffing over time.
#
# Usage:
#   sudo ./audit-linux-hardening.sh [-o OUTPUT_DIR] [-n HOSTNAME_LABEL]
#
# Exit codes:
#   0 = ran successfully (score may still be low — check the report)
#   1 = fatal error before checks could run
#
# Tested target: Debian/Ubuntu and RHEL/CentOS family. Checks degrade
# gracefully (status = "Info / not applicable") when a subsystem
# (e.g. SELinux on a Debian box) isn't present, rather than failing loudly.

set -uo pipefail

# ---------------------------------------------------------------------------
# Config / CLI
# ---------------------------------------------------------------------------
OUTPUT_DIR="./reports"
HOST_LABEL="$(hostname 2>/dev/null || echo unknown-host)"

while getopts "o:n:h" opt; do
  case "$opt" in
    o) OUTPUT_DIR="$OPTARG" ;;
    n) HOST_LABEL="$OPTARG" ;;
    h)
      echo "Usage: $0 [-o output_dir] [-n hostname_label]"
      exit 0
      ;;
    *) ;;
  esac
done

mkdir -p "$OUTPUT_DIR"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
FILE_STAMP="$(date +"%Y%m%d-%H%M%S")"
JSON_OUT="$OUTPUT_DIR/linux-hardening-${FILE_STAMP}.json"
HTML_OUT="$OUTPUT_DIR/linux-hardening-${FILE_STAMP}.html"

IS_ROOT=0
if [ "$(id -u)" -eq 0 ]; then IS_ROOT=1; fi

# ---------------------------------------------------------------------------
# Check registry
# Each check appends one line to CHECKS_TSV:
#   id \t category \t title \t severity \t status \t found \t expected \t remediation \t cis_ref
# status is one of: PASS FAIL WARN INFO
# severity is one of: Critical High Medium Low   (severity is scored only on FAIL)
# ---------------------------------------------------------------------------
CHECKS_TSV="$(mktemp)"

add_check() {
  # $1 id  $2 category  $3 title  $4 severity  $5 status  $6 found  $7 expected  $8 remediation  $9 cis_ref
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" >> "$CHECKS_TSV"
}

esc() {
  # Escape tabs/newlines out of a value so it survives the TSV round trip.
  printf '%s' "$1" | tr '\t\n' '  ' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# ---------------------------------------------------------------------------
# 1. SSH hardening (CIS 5.2.x)
# ---------------------------------------------------------------------------
check_ssh() {
  local sshd_config="/etc/ssh/sshd_config"
  if [ ! -f "$sshd_config" ]; then
    add_check "SSH-01" "Remote Access" "SSH daemon config present" "Medium" "INFO" \
      "no sshd_config found" "N/A" "SSH not installed — not applicable" "CIS 5.2"
    return
  fi

  local effective
  if command -v sshd >/dev/null 2>&1 && [ "$IS_ROOT" -eq 1 ]; then
    effective="$(sshd -T 2>/dev/null)"
  else
    effective=""
  fi

  get_val() {
    local key="$1"
    local v
    if [ -n "$effective" ]; then
      v="$(printf '%s\n' "$effective" | awk -v k="$key" 'tolower($1)==tolower(k){print $2; exit}')"
    fi
    if [ -z "${v:-}" ]; then
      v="$(grep -iE "^\s*${key}\s" "$sshd_config" 2>/dev/null | awk '{print $2}' | tail -1)"
    fi
    echo "${v:-not set}"
  }

  local root_login pass_auth permit_empty proto x11 maxauth
  root_login="$(get_val PermitRootLogin)"
  pass_auth="$(get_val PasswordAuthentication)"
  permit_empty="$(get_val PermitEmptyPasswords)"
  x11="$(get_val X11Forwarding)"
  maxauth="$(get_val MaxAuthTries)"

  if [[ "$root_login" =~ ^(no)$ ]]; then
    add_check "SSH-02" "Remote Access" "Root login over SSH disabled" "Critical" "PASS" "$root_login" "no" "N/A" "CIS 5.2.10"
  else
    add_check "SSH-02" "Remote Access" "Root login over SSH disabled" "Critical" "FAIL" "$root_login" "no" \
      "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd. Use sudo for admin access instead." "CIS 5.2.10"
  fi

  if [[ "$pass_auth" == "no" ]]; then
    add_check "SSH-03" "Remote Access" "SSH password authentication disabled (keys only)" "High" "PASS" "$pass_auth" "no" "N/A" "CIS 5.2.8"
  else
    add_check "SSH-03" "Remote Access" "SSH password authentication disabled (keys only)" "High" "FAIL" "$pass_auth" "no" \
      "Set 'PasswordAuthentication no' once SSH keys are deployed for all admins, then restart sshd." "CIS 5.2.8"
  fi

  if [[ "$permit_empty" == "no" || "$permit_empty" == "not set" ]]; then
    add_check "SSH-04" "Remote Access" "Empty passwords not permitted over SSH" "Critical" "PASS" "$permit_empty" "no" "N/A" "CIS 5.2.9"
  else
    add_check "SSH-04" "Remote Access" "Empty passwords not permitted over SSH" "Critical" "FAIL" "$permit_empty" "no" \
      "Set 'PermitEmptyPasswords no' in sshd_config." "CIS 5.2.9"
  fi

  if [[ "$x11" == "no" ]]; then
    add_check "SSH-05" "Remote Access" "X11 forwarding disabled" "Low" "PASS" "$x11" "no" "N/A" "CIS 5.2.14"
  else
    add_check "SSH-05" "Remote Access" "X11 forwarding disabled" "Low" "WARN" "$x11" "no" \
      "Disable X11Forwarding unless remote GUI access is genuinely required." "CIS 5.2.14"
  fi

  if [[ "$maxauth" != "not set" && "$maxauth" -le 4 ]] 2>/dev/null; then
    add_check "SSH-06" "Remote Access" "SSH MaxAuthTries limited (brute-force resistance)" "Medium" "PASS" "$maxauth" "<=4" "N/A" "CIS 5.2.5"
  else
    add_check "SSH-06" "Remote Access" "SSH MaxAuthTries limited (brute-force resistance)" "Medium" "WARN" "$maxauth" "<=4" \
      "Set 'MaxAuthTries 4' (or lower) in sshd_config to slow brute-force attempts." "CIS 5.2.5"
  fi
}

# ---------------------------------------------------------------------------
# 2. Firewall (CIS 3.x / 4.x)
# ---------------------------------------------------------------------------
check_firewall() {
  local active="no" tool="none"
  if command -v ufw >/dev/null 2>&1; then
    tool="ufw"
    if ufw status 2>/dev/null | grep -qi "Status: active"; then active="yes"; fi
  fi
  if [ "$active" = "no" ] && command -v firewall-cmd >/dev/null 2>&1; then
    tool="firewalld"
    if firewall-cmd --state 2>/dev/null | grep -qi running; then active="yes"; fi
  fi
  if [ "$active" = "no" ] && command -v nft >/dev/null 2>&1; then
    if nft list ruleset 2>/dev/null | grep -q .; then active="yes"; tool="nftables"; fi
  fi
  if [ "$active" = "no" ] && command -v iptables >/dev/null 2>&1; then
    local rule_count
    rule_count="$(iptables -S 2>/dev/null | wc -l)"
    if [ "${rule_count:-0}" -gt 3 ]; then active="yes"; tool="iptables"; fi
  fi

  if [ "$active" = "yes" ]; then
    add_check "FW-01" "Network" "Host firewall active" "Critical" "PASS" "$tool active" "an active firewall" "N/A" "CIS 3.5"
  else
    add_check "FW-01" "Network" "Host firewall active" "Critical" "FAIL" "no active firewall detected" "an active firewall" \
      "Enable ufw ('sudo ufw enable') or firewalld ('sudo systemctl enable --now firewalld') and define default-deny inbound rules." "CIS 3.5"
  fi
}

# ---------------------------------------------------------------------------
# 3. Mandatory access control — SELinux / AppArmor (CIS 1.6.x)
# ---------------------------------------------------------------------------
check_mac() {
  if command -v getenforce >/dev/null 2>&1; then
    local mode
    mode="$(getenforce 2>/dev/null)"
    if [ "$mode" = "Enforcing" ]; then
      add_check "MAC-01" "System Hardening" "SELinux enforcing" "High" "PASS" "$mode" "Enforcing" "N/A" "CIS 1.6.1"
    elif [ "$mode" = "Permissive" ]; then
      add_check "MAC-01" "System Hardening" "SELinux enforcing" "High" "WARN" "$mode" "Enforcing" \
        "SELinux is loaded but only logging violations. Set SELINUX=enforcing in /etc/selinux/config once policy is validated." "CIS 1.6.1"
    else
      add_check "MAC-01" "System Hardening" "SELinux enforcing" "High" "FAIL" "$mode" "Enforcing" \
        "Enable SELinux enforcing mode, or install AppArmor if this distro doesn't ship SELinux." "CIS 1.6.1"
    fi
  elif command -v aa-status >/dev/null 2>&1; then
    local profiles_enforced
    profiles_enforced="$(aa-status --enforced 2>/dev/null | head -1)"
    if aa-status --enabled >/dev/null 2>&1; then
      add_check "MAC-01" "System Hardening" "AppArmor enabled and enforcing profiles" "High" "PASS" \
        "AppArmor active, ${profiles_enforced:-profiles} enforced" "AppArmor enabled" "N/A" "CIS 1.6.1"
    else
      add_check "MAC-01" "System Hardening" "AppArmor enabled and enforcing profiles" "High" "FAIL" \
        "AppArmor installed but not enabled" "AppArmor enabled" \
        "Run 'sudo systemctl enable --now apparmor' and set profiles to enforce mode with aa-enforce." "CIS 1.6.1"
    fi
  else
    add_check "MAC-01" "System Hardening" "Mandatory access control (SELinux/AppArmor) present" "High" "FAIL" \
      "neither SELinux nor AppArmor found" "SELinux or AppArmor enabled" \
      "Install and enable AppArmor ('apt install apparmor apparmor-utils') or SELinux depending on distro." "CIS 1.6.1"
  fi
}

# ---------------------------------------------------------------------------
# 4. Critical file permissions (CIS 6.1.x)
# ---------------------------------------------------------------------------
check_file_perms() {
  check_perm() {
    local path="$1" max_octal="$2" id="$3" label="$4" cis="$5"
    if [ ! -e "$path" ]; then
      add_check "$id" "File Permissions" "$label" "Medium" "INFO" "file not found" "$path exists" "N/A" "$cis"
      return
    fi
    local perm
    perm="$(stat -c '%a' "$path" 2>/dev/null)"
    if [ -z "$perm" ]; then
      add_check "$id" "File Permissions" "$label" "Medium" "INFO" "unable to stat" "mode <= $max_octal" "N/A" "$cis"
      return
    fi
    if [ "$perm" -le "$max_octal" ] 2>/dev/null; then
      add_check "$id" "File Permissions" "$label" "High" "PASS" "mode $perm" "mode <= $max_octal" "N/A" "$cis"
    else
      add_check "$id" "File Permissions" "$label" "High" "FAIL" "mode $perm" "mode <= $max_octal" \
        "Run 'sudo chmod $max_octal $path' to restrict access." "$cis"
    fi
  }
  check_perm "/etc/passwd" 644 "PERM-01" "/etc/passwd permissions restricted" "CIS 6.1.2"
  check_perm "/etc/shadow" 640 "PERM-02" "/etc/shadow permissions restricted" "CIS 6.1.3"
  check_perm "/etc/gshadow" 640 "PERM-03" "/etc/gshadow permissions restricted" "CIS 6.1.5"
  check_perm "/etc/group" 644 "PERM-04" "/etc/group permissions restricted" "CIS 6.1.4"

  # World-writable files outside expected pseudo-filesystems (sampled, time-boxed).
  local ww_count
  ww_count="$(timeout 8 find / -xdev -type f -perm -0002 \
      -not -path "/proc/*" -not -path "/sys/*" -not -path "/tmp/*" -not -path "/var/tmp/*" \
      2>/dev/null | wc -l)"
  if [ "$ww_count" -eq 0 ]; then
    add_check "PERM-05" "File Permissions" "No unexpected world-writable files on root filesystem" "Medium" "PASS" \
      "0 found" "0" "N/A" "CIS 6.1.9"
  else
    add_check "PERM-05" "File Permissions" "No unexpected world-writable files on root filesystem" "Medium" "WARN" \
      "$ww_count found" "0" \
      "Review world-writable files with 'find / -xdev -type f -perm -0002' and tighten permissions or move to /tmp." "CIS 6.1.9"
  fi
}

# ---------------------------------------------------------------------------
# 5. Account security (CIS 5.4.x, 6.2.x)
# ---------------------------------------------------------------------------
check_accounts() {
  # Empty passwords
  local empty_pw
  empty_pw="$(awk -F: '($2 == "" ) {print $1}' /etc/shadow 2>/dev/null | wc -l)"
  if [ "$IS_ROOT" -eq 0 ]; then
    add_check "ACC-01" "Account Security" "No accounts with empty passwords" "Critical" "INFO" \
      "requires root to read /etc/shadow" "0 empty passwords" "Re-run this script with sudo for a definitive result." "CIS 6.2.1"
  elif [ "$empty_pw" -eq 0 ]; then
    add_check "ACC-01" "Account Security" "No accounts with empty passwords" "Critical" "PASS" "0" "0" "N/A" "CIS 6.2.1"
  else
    add_check "ACC-01" "Account Security" "No accounts with empty passwords" "Critical" "FAIL" "$empty_pw account(s)" "0" \
      "Lock or set a password for every account listed by: awk -F: '(\$2==\"\"){print \$1}' /etc/shadow" "CIS 6.2.1"
  fi

  # Duplicate UID 0 accounts (besides root)
  local dup_uid0
  dup_uid0="$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd 2>/dev/null | wc -l)"
  if [ "$dup_uid0" -eq 0 ]; then
    add_check "ACC-02" "Account Security" "Only 'root' has UID 0" "Critical" "PASS" "0 extra" "0" "N/A" "CIS 6.2.9"
  else
    add_check "ACC-02" "Account Security" "Only 'root' has UID 0" "Critical" "FAIL" "$dup_uid0 extra UID-0 account(s)" "0" \
      "Investigate and remove/rename any non-root account with UID 0 — this is a common backdoor technique." "CIS 6.2.9"
  fi

  # Password aging policy
  local max_days
  max_days="$(awk '/^PASS_MAX_DAYS/{print $2}' /etc/login.defs 2>/dev/null)"
  if [ -n "$max_days" ] && [ "$max_days" -le 90 ] 2>/dev/null; then
    add_check "ACC-03" "Account Security" "Password max age <= 90 days" "Medium" "PASS" "$max_days days" "<= 90" "N/A" "CIS 5.4.1.1"
  else
    add_check "ACC-03" "Account Security" "Password max age <= 90 days" "Medium" "WARN" "${max_days:-unset}" "<= 90" \
      "Set PASS_MAX_DAYS 90 in /etc/login.defs (applies to newly created accounts; use chage for existing ones)." "CIS 5.4.1.1"
  fi

  # sudoers NOPASSWD entries
  local nopasswd_count=0
  if [ "$IS_ROOT" -eq 1 ] && command -v grep >/dev/null 2>&1; then
    nopasswd_count="$( (grep -rE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null) | wc -l)"
  fi
  if [ "$IS_ROOT" -eq 0 ]; then
    add_check "ACC-04" "Account Security" "No blanket NOPASSWD sudo rules" "Medium" "INFO" \
      "requires root to read sudoers" "0" "Re-run with sudo for a definitive result." "CIS 5.3"
  elif [ "$nopasswd_count" -eq 0 ]; then
    add_check "ACC-04" "Account Security" "No blanket NOPASSWD sudo rules" "Medium" "PASS" "0" "0" "N/A" "CIS 5.3"
  else
    add_check "ACC-04" "Account Security" "No blanket NOPASSWD sudo rules" "Medium" "WARN" "$nopasswd_count rule(s)" "0" \
      "Review /etc/sudoers and /etc/sudoers.d/ for NOPASSWD entries; require passwords for privileged commands where practical." "CIS 5.3"
  fi
}

# ---------------------------------------------------------------------------
# 6. Patch management (CIS 1.9)
# ---------------------------------------------------------------------------
check_updates() {
  if command -v apt-get >/dev/null 2>&1; then
    local upgradable
    upgradable="$(apt list --upgradable 2>/dev/null | grep -c upgradable)"
    if [ "$upgradable" -eq 0 ]; then
      add_check "UPD-01" "Patch Management" "System packages up to date" "High" "PASS" "0 pending" "0" "N/A" "CIS 1.9"
    else
      add_check "UPD-01" "Patch Management" "System packages up to date" "High" "WARN" "$upgradable package(s) pending" "0" \
        "Run 'sudo apt-get update && sudo apt-get upgrade' and reboot if a kernel update was applied." "CIS 1.9"
    fi
    if dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
      add_check "UPD-02" "Patch Management" "Automatic security updates configured" "Medium" "PASS" "unattended-upgrades installed" "installed" "N/A" "CIS 1.9"
    else
      add_check "UPD-02" "Patch Management" "Automatic security updates configured" "Medium" "WARN" "not installed" "installed" \
        "Install unattended-upgrades ('sudo apt-get install unattended-upgrades') so security patches apply automatically." "CIS 1.9"
    fi
  elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    local pkgmgr; pkgmgr="$(command -v dnf || command -v yum)"
    local upgradable
    upgradable="$($pkgmgr check-update 2>/dev/null | grep -cE '^[a-zA-Z0-9]')"
    if [ "${upgradable:-0}" -eq 0 ]; then
      add_check "UPD-01" "Patch Management" "System packages up to date" "High" "PASS" "0 pending" "0" "N/A" "CIS 1.9"
    else
      add_check "UPD-01" "Patch Management" "System packages up to date" "High" "WARN" "$upgradable package(s) pending" "0" \
        "Run 'sudo $pkgmgr update' and reboot if a kernel update was applied." "CIS 1.9"
    fi
  else
    add_check "UPD-01" "Patch Management" "System packages up to date" "High" "INFO" "unsupported package manager" "N/A" \
      "Check for updates manually using this distro's package manager." "CIS 1.9"
  fi
}

# ---------------------------------------------------------------------------
# 7. SUID/SGID audit (CIS 6.1.13/14 — informational, sampled)
# ---------------------------------------------------------------------------
check_suid() {
  local count
  count="$(timeout 10 find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l)"
  # Informational baseline: flag only if unusually high (rough heuristic).
  if [ "$count" -le 40 ]; then
    add_check "SUID-01" "System Hardening" "SUID/SGID binary count within normal range" "Low" "PASS" "$count found" "<= 40 (heuristic)" "N/A" "CIS 6.1.13"
  else
    add_check "SUID-01" "System Hardening" "SUID/SGID binary count within normal range" "Low" "WARN" "$count found" "<= 40 (heuristic)" \
      "Review the SUID/SGID inventory ('find / -xdev -type f \\( -perm -4000 -o -perm -2000 \\)') for anything unexpected." "CIS 6.1.13"
  fi
}

# ---------------------------------------------------------------------------
# 8. Core services exposure (CIS 2.2.x — sampled common risky services)
# ---------------------------------------------------------------------------
check_services() {
  local risky=("telnet" "rsh-server" "vsftpd" "xinetd" "nis" "tftp-server")
  local found=()
  for svc in "${risky[@]}"; do
    if systemctl is-enabled "$svc" >/dev/null 2>&1; then
      found+=("$svc")
    fi
  done
  if [ "${#found[@]}" -eq 0 ]; then
    add_check "SVC-01" "System Hardening" "No legacy insecure services enabled (telnet, ftp, rsh, tftp, NIS)" "High" "PASS" "none found" "none" "N/A" "CIS 2.2"
  else
    add_check "SVC-01" "System Hardening" "No legacy insecure services enabled (telnet, ftp, rsh, tftp, NIS)" "High" "FAIL" \
      "${found[*]}" "none" "Disable and remove these services: 'sudo systemctl disable --now <service>' then uninstall the package." "CIS 2.2"
  fi
}

# ---------------------------------------------------------------------------
# Run all checks
# ---------------------------------------------------------------------------
check_ssh
check_firewall
check_mac
check_file_perms
check_accounts
check_updates
check_suid
check_services

# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
sev_weight() {
  case "$1" in
    Critical) echo 10 ;;
    High) echo 7 ;;
    Medium) echo 4 ;;
    Low) echo 2 ;;
    *) echo 1 ;;
  esac
}

TOTAL_WEIGHT=0
EARNED_WEIGHT=0
PASS_N=0; FAIL_N=0; WARN_N=0; INFO_N=0

while IFS=$'\t' read -r id category title severity status found expected remediation cis; do
  w="$(sev_weight "$severity")"
  case "$status" in
    PASS) TOTAL_WEIGHT=$((TOTAL_WEIGHT + w)); EARNED_WEIGHT=$((EARNED_WEIGHT + w)); PASS_N=$((PASS_N+1)) ;;
    FAIL) TOTAL_WEIGHT=$((TOTAL_WEIGHT + w)); FAIL_N=$((FAIL_N+1)) ;;
    WARN) TOTAL_WEIGHT=$((TOTAL_WEIGHT + w)); EARNED_WEIGHT=$((EARNED_WEIGHT + w/2)); WARN_N=$((WARN_N+1)) ;;
    INFO) INFO_N=$((INFO_N+1)) ;;
  esac
done < "$CHECKS_TSV"

SCORE=100
if [ "$TOTAL_WEIGHT" -gt 0 ]; then
  SCORE=$(( (EARNED_WEIGHT * 100) / TOTAL_WEIGHT ))
fi

grade_for() {
  local s="$1"
  if [ "$s" -ge 90 ]; then echo "A"
  elif [ "$s" -ge 80 ]; then echo "B"
  elif [ "$s" -ge 70 ]; then echo "C"
  elif [ "$s" -ge 60 ]; then echo "D"
  else echo "F"; fi
}
GRADE="$(grade_for "$SCORE")"

# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------
{
  echo "{"
  echo "  \"scan_type\": \"linux\","
  echo "  \"host\": \"$(esc "$HOST_LABEL")\","
  echo "  \"timestamp_utc\": \"$TIMESTAMP\","
  echo "  \"ran_as_root\": $( [ "$IS_ROOT" -eq 1 ] && echo true || echo false ),"
  echo "  \"score\": $SCORE,"
  echo "  \"grade\": \"$GRADE\","
  echo "  \"summary\": { \"pass\": $PASS_N, \"fail\": $FAIL_N, \"warn\": $WARN_N, \"info\": $INFO_N },"
  echo "  \"checks\": ["
  local_first=1
  while IFS=$'\t' read -r id category title severity status found expected remediation cis; do
    if [ "$local_first" -eq 0 ]; then echo "    ,"; fi
    local_first=0
    printf '    { "id": "%s", "category": "%s", "title": "%s", "severity": "%s", "status": "%s", "found": "%s", "expected": "%s", "remediation": "%s", "cis_ref": "%s" }\n' \
      "$(esc "$id")" "$(esc "$category")" "$(esc "$title")" "$(esc "$severity")" "$(esc "$status")" \
      "$(esc "$found")" "$(esc "$expected")" "$(esc "$remediation")" "$(esc "$cis")"
  done < "$CHECKS_TSV"
  echo "  ]"
  echo "}"
} > "$JSON_OUT"

# ---------------------------------------------------------------------------
# HTML output — delegate to shared renderer
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RENDERER="$SCRIPT_DIR/../render-report.sh"
if [ -f "$RENDERER" ]; then
  # shellcheck source=/dev/null
  source "$RENDERER"
  render_html_report "$JSON_OUT" "$HTML_OUT" "Linux Hardening Report — $HOST_LABEL"
fi

rm -f "$CHECKS_TSV"

echo "Linux hardening audit complete."
echo "  Score: $SCORE / 100 (Grade $GRADE)"
echo "  Pass: $PASS_N  Fail: $FAIL_N  Warn: $WARN_N  Info: $INFO_N"
echo "  JSON: $JSON_OUT"
[ -f "$HTML_OUT" ] && echo "  HTML: $HTML_OUT"
if [ "$IS_ROOT" -eq 0 ]; then
  echo "  NOTE: not run as root — some checks (shadow file, sudoers) are marked Info/limited. Re-run with sudo for full coverage."
fi
