# Windows/Linux Hardening Auditor (Module 2)

A pair of scripts that check a live Windows or Linux machine against a
CIS-style hardening baseline and produce a **scored, severity-ranked HTML
report** a non-security person (e.g. a cyber cafe owner) can act on,
plus a JSON file for automation or tracking drift over time.

Built for the reality of cyber cafes and small offices in Kenya: machines
that are often unpatched, misconfigured, and managed by someone without a
security background. The report is written to be readable without jargon
translation — every failed check includes a plain-language fix.

## Files

```
hardening-auditor/
├── windows/
│   └── Audit-WindowsHardening.ps1   # Run on Windows, in an elevated PowerShell prompt
├── linux/
│   └── audit-linux-hardening.sh     # Run on Linux, with sudo
├── render-report.sh                 # Shared HTML renderer (sourced by the Linux script)
├── sample-reports/                  # Example output from a live run
└── README.md
```

Both scripts emit the **same JSON schema**, so the HTML report looks and
behaves identically regardless of platform — useful if you're auditing a
mixed fleet (which is exactly what a Kenyan cyber cafe usually is: a couple
of Windows desktops for customers, a Linux box running the router/print
server).

## Usage

**Windows** (run PowerShell as Administrator for full coverage — it still
runs without admin, just with more checks marked "Info" instead of a real
result):

```powershell
.\Audit-WindowsHardening.ps1 -OutputDir .\reports
```

**Linux** (run with `sudo` for full coverage — same graceful-degrade
behavior without root):

```bash
sudo ./audit-linux-hardening.sh -o ./reports -n "front-desk-pc"
```

Both drop a timestamped `.json` and `.html` file in the output directory.
Open the `.html` file in any browser — it's fully self-contained (JSON is
embedded, no external files or internet connection needed), and prints
cleanly to PDF via the browser's Print dialog if a PDF copy is wanted.

## Baseline checklist (CIS-style controls)

### Windows
| Category | Checks |
|---|---|
| Access Control | UAC enabled, UAC consent-on-elevation |
| Network | Firewall enabled per profile (Domain/Private/Public), SMBv1 disabled |
| Account Security | Guest account disabled, built-in Administrator disabled/renamed, local Administrators group membership size |
| Password Policy | Minimum password length ≥ 14, account lockout threshold configured |
| Remote Access | RDP disabled unless needed, RDP requires Network Level Authentication |
| Endpoint Protection | Real-time AV active, signatures ≤ 7 days old |
| Patch Management | Windows Update service not disabled, recent patches applied (≤ 45 days) |
| Registry Hardening | AutoAdminLogon disabled, LLMNR disabled, password-protected screen lock |
| System Hardening | PowerShell execution policy, Script Block Logging enabled |

Mapped to CIS Microsoft Windows Benchmark control families 1.x, 2.3.x,
5.x, 9.x, and 18.x.

### Linux
| Category | Checks |
|---|---|
| Remote Access | SSH root login disabled, password auth disabled, empty passwords blocked, X11 forwarding off, MaxAuthTries limited |
| Network | Host firewall active (ufw/firewalld/nftables/iptables) |
| System Hardening | SELinux enforcing or AppArmor enabled, SUID/SGID binary count, no legacy insecure services (telnet/ftp/rsh/tftp/NIS) |
| File Permissions | `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, `/etc/group` modes, no unexpected world-writable files |
| Account Security | No empty-password accounts, only `root` has UID 0, password max-age ≤ 90 days, no blanket `NOPASSWD` sudo rules |
| Patch Management | No pending package upgrades, automatic security updates configured |

Mapped to CIS Distribution Independent Linux Benchmark control families
1.6.x, 1.9, 2.2, 3.5, 5.2.x, 5.3, 5.4.x, 6.1.x, 6.2.x.

Each script's source comments include the exact CIS control reference next
to each check, so the mapping is traceable back to the benchmark rather
than invented ad hoc.

## Scoring

Every check has a severity (**Critical / High / Medium / Low**), weighted
10 / 7 / 4 / 2 respectively. A passed check earns its full weight; a
`WARN` (partial compliance, e.g. a setting present but not ideal) earns
half; a failed check earns nothing. The overall score is
`(earned weight / possible weight) × 100`, graded A (90+) through F (<60).
Checks that can't be evaluated at all (e.g. no root/admin rights, feature
not installed) are marked `INFO` and excluded from scoring rather than
counted as a fail — a missing capability isn't the same as a
misconfiguration.

## Design notes / what I'd improve next

- Both scripts are **read-only** — they audit and report but never change
  system state, which is deliberate: this is meant to run unattended on a
  customer's production machine without a "trust me" moment.
- Checks degrade to `INFO` rather than crashing when a cmdlet/tool is
  missing or permissions are insufficient — important on real cyber cafe
  hardware, which varies a lot (Windows Home vs Pro, non-domain-joined,
  different Linux distros).
- Next iteration: a `--baseline diff` mode that compares two JSON reports
  from the same host over time to flag configuration drift, and a
  lightweight cron/Scheduled Task wrapper for recurring audits.
