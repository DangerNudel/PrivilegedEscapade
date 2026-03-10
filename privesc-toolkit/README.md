# PrivEscalation Assessor v1.0

## MITRE ATT&CK TA0004 - Privilege Escalation Assessment Toolkit

A comprehensive, Go-based defensive security assessment toolkit that enumerates and detects privilege escalation vectors on Linux systems, mapped to MITRE ATT&CK TA0004 techniques. Built for cybersecurity education, lab instruction, and authorized security assessments.

> **⚠ AUTHORIZED USE ONLY** — This tool performs detection and assessment only. It identifies potential privilege escalation vectors but does NOT exploit them. Use only on systems you are authorized to assess.

---

## Features

- **Full MITRE ATT&CK TA0004 Coverage** — 13 parent techniques, 60+ sub-techniques mapped
- **9 Assessment Modules** covering all major privilege escalation categories
- **Interactive TUI** with menu-driven module selection and post-assessment analysis
- **CLI Mode** for automated/scripted assessments (CI/CD, batch scanning)
- **Severity Scoring** — CRITICAL/HIGH/MEDIUM/LOW/INFO with numeric risk scores (0-100)
- **MITRE Technique Heatmap** — Visual coverage map showing findings per technique
- **Multi-Format Export** — JSON (SIEM-ingestible) and Markdown reports
- **Zero Dependencies** — Pure Go standard library, single static binary
- **Cross-Compilation** — Build for Linux amd64/arm64 from any platform

---

## Quick Start

### Prerequisites

- Go 1.21+ (for building from source)
- Linux target system (assessment modules are Linux-focused)
- Root or sudo access recommended for full assessment coverage

### Build

```bash
# Clone or copy the project
cd privesc-toolkit

# Build for current platform
go build -o privesc-assess .

# Cross-compile for other architectures
GOOS=linux GOARCH=amd64 go build -o privesc-assess-linux-amd64 .
GOOS=linux GOARCH=arm64 go build -o privesc-assess-linux-arm64 .
```

### Run

```bash
# Interactive mode (default) — full TUI with menus
./privesc-assess

# Automated mode — run all modules, output to terminal
./privesc-assess -auto

# Automated with JSON + Markdown export
./privesc-assess -auto -json report.json -md report.md

# Show help
./privesc-assess -help
```

---

## Assessment Modules

| # | Module | MITRE Techniques | Description |
|---|--------|-----------------|-------------|
| 1 | **SUID/SGID Binary Analysis** | T1548, T1548.001 | Scans for dangerous SUID/SGID binaries, writable SUID directories, 50+ known GTFOBins mappings |
| 2 | **Sudo Configuration Analysis** | T1548, T1548.003 | Analyzes sudo -l output, NOPASSWD entries, dangerous commands, env_keep, sudo version CVEs, timestamp caching |
| 3 | **Kernel & Exploit Vector Analysis** | T1068 | Kernel version CVE checks (DirtyPipe, PwnKit, GameOverlay, etc.), kernel protection auditing (ASLR, ptrace, kptr_restrict), module analysis, compiler availability |
| 4 | **Scheduled Task & Cron Analysis** | T1053, T1053.002, T1053.003, T1053.006 | System/user crontabs, cron.d scripts, at jobs, systemd timers, wildcard injection, writable cron scripts, access control |
| 5 | **System Service & Daemon Analysis** | T1543, T1543.002 | Systemd unit files, init.d scripts, writable service binaries, D-Bus configs, rc.local analysis |
| 6 | **Execution Flow Hijacking** | T1574, T1574.006, T1574.007 | PATH directory analysis, LD_PRELOAD/LD_LIBRARY_PATH checks, ld.so.conf audit, library directory permissions, Linux capabilities, RPATH analysis on SUID binaries |
| 7 | **Container Escape & Environment** | T1611 | Docker socket access, privileged container detection, host mount analysis, cgroup escape vectors, Kubernetes service accounts, dangerous group memberships |
| 8 | **Account & Credential Analysis** | T1078, T1078.001, T1078.003 | /etc/passwd & shadow analysis, UID 0 accounts, empty passwords, SSH key access, credential file discovery, PAM configuration, history file analysis |
| 9 | **Shell & Event-Triggered Execution** | T1546, T1546.004, T1546.005, T1547 | Global/user shell configs, profile.d scripts, XDG autostart, suspicious content detection (reverse shells, credential capture aliases, LD_PRELOAD injection), MOTD scripts |

---

## Interactive TUI

The default mode provides a full terminal user interface:

```
┌─────────────────────────────────────────┐
│  MAIN MENU                              │
├─────────────────────────────────────────┤
│  [1]  Run Full Assessment (All Modules) │
│  [2]  Select Individual Modules         │
│  [3]  View Technique Coverage Map       │
│  [4]  MITRE ATT&CK Reference Browser   │
│  [5]  Export Settings                   │
│  [Q]  Quit                              │
└─────────────────────────────────────────┘
```

After assessment, the post-assessment menu provides:
- **Detailed Findings View** — Sorted by risk score with evidence and remediation
- **Technique Heatmap** — Visual MITRE ATT&CK coverage with severity indicators
- **JSON Export** — Machine-readable, SIEM-ingestible format
- **Markdown Export** — Human-readable report for documentation

---

## CLI Flags

| Flag | Description |
|------|-------------|
| `-auto` | Non-interactive mode, run all modules |
| `-i` | Explicitly request interactive mode |
| `-json <file>` | Export JSON report to file |
| `-md <file>` | Export Markdown report to file |
| `-modules <list>` | Module filter (default: "all") |
| `-version` | Show version |

---

## Report Formats

### JSON Report Structure

```json
{
  "meta": {
    "hostname": "target-host",
    "os": "linux",
    "arch": "amd64",
    "user": "assessor",
    "timestamp": "2024-01-15T10:30:00Z",
    "duration": "2m30s"
  },
  "summary": {
    "total_findings": 34,
    "critical": 14,
    "high": 8,
    "medium": 6,
    "low": 2,
    "info": 4
  },
  "modules": [
    {
      "module": "SUID/SGID Binary Analysis",
      "duration": "1m4s",
      "findings": [
        {
          "technique_id": "T1548.001",
          "technique": "Abuse Elevation Control Mechanism",
          "sub_technique": "Setuid and Setgid",
          "severity": "CRITICAL",
          "detail": "Dangerous SUID binary found: /usr/bin/mount",
          "evidence": "mount can be abused to mount attacker-controlled filesystems",
          "remediation": "Remove SUID bit: chmod u-s /usr/bin/mount (if not required)",
          "risk_score": 95
        }
      ]
    }
  ]
}
```

---

## MITRE ATT&CK TA0004 Technique Coverage

```
Technique ID    Name                                    Status
─────────────────────────────────────────────────────────────
T1548           Abuse Elevation Control Mechanism       ✓ Assessed
  T1548.001       Setuid and Setgid                    ✓ SUID/SGID scan
  T1548.002       Bypass UAC                           ○ Windows only
  T1548.003       Sudo and Sudo Caching                ✓ Sudo module
  T1548.004       Elevated Execution with Prompt       ○ macOS only
T1134           Access Token Manipulation               ○ Windows only
T1547           Boot or Logon Autostart Execution       ✓ Assessed
  T1547.006       Kernel Modules and Extensions        ✓ Kernel module
  T1547.013       XDG Autostart Entries                ✓ Shell module
T1037           Boot or Logon Initialization Scripts    ✓ Assessed
  T1037.004       RC Scripts                           ✓ Service module
T1543           Create or Modify System Process         ✓ Assessed
  T1543.002       Systemd Service                      ✓ Service module
T1484           Domain/Tenant Policy Modification       ○ AD environment
T1546           Event Triggered Execution               ✓ Assessed
  T1546.004       Unix Shell Configuration             ✓ Shell module
  T1546.005       Trap                                 ✓ Shell module
T1068           Exploitation for Privilege Escalation   ✓ Assessed
T1574           Hijack Execution Flow                   ✓ Assessed
  T1574.006       Dynamic Linker Hijacking             ✓ Path module
  T1574.007       PATH Environment Variable            ✓ Path module
T1055           Process Injection                       ✓ Assessed
  T1055.008       Ptrace System Calls                  ✓ Container module
T1053           Scheduled Task/Job                      ✓ Assessed
  T1053.002       At                                   ✓ Cron module
  T1053.003       Cron                                 ✓ Cron module
  T1053.006       Systemd Timers                       ✓ Cron module
T1078           Valid Accounts                          ✓ Assessed
  T1078.001       Default Accounts                     ✓ Account module
  T1078.003       Local Accounts                       ✓ Account module
T1611           Escape to Host                          ✓ Assessed
```

---

## Project Architecture

```
privesc-toolkit/
├── main.go                          # Entry point, CLI/TUI orchestration
├── go.mod                           # Go module definition (zero deps)
├── internal/
│   ├── assessor/
│   │   ├── common.go                # Shared types (Module interface, stats)
│   │   ├── suid.go                  # SUID/SGID binary analysis
│   │   ├── sudo.go                  # Sudo configuration checks
│   │   ├── kernel.go                # Kernel CVEs and protections
│   │   ├── cron.go                  # Cron/at/systemd timer analysis
│   │   ├── services.go              # Systemd/init service analysis
│   │   ├── path_hijack.go           # PATH/LD/library/capability checks
│   │   ├── container.go             # Docker/K8s/container escape
│   │   ├── accounts.go              # User/credential/SSH analysis
│   │   └── shell_env.go             # Shell config/autostart/events
│   ├── mitre/
│   │   └── mapping.go               # Full TA0004 technique database
│   ├── report/
│   │   └── report.go                # Summary, detailed, heatmap, exports
│   └── tui/
│       └── tui.go                   # Terminal UI menus and widgets
└── README.md                        # This file
```

**Total: ~4,400 lines of Go | 15 source files | Zero external dependencies**

---

## Classroom Lab Usage

This toolkit is designed for cybersecurity education environments:

1. **Vulnerability Assessment Lab** — Students run the tool against intentionally misconfigured VMs and analyze findings
2. **MITRE ATT&CK Mapping Exercise** — Use the heatmap to understand technique-to-detection relationships
3. **Hardening Workshop** — Students remediate findings using the provided fix commands
4. **Report Analysis** — Import JSON reports into SIEM tools (Splunk, Elastic) for correlation exercises
5. **Red vs Blue Exercise** — Red team introduces misconfigurations, blue team detects with this tool

### Suggested Lab Setup

```bash
# Deploy to isolated lab network
scp privesc-assess student@lab-vm:~/

# Run full assessment as unprivileged user
ssh student@lab-vm './privesc-assess -auto -json student_report.json'

# Run again as root for comparison
ssh root@lab-vm './privesc-assess -auto -json root_report.json'

# Compare findings between privileged and unprivileged runs
```

---

## Extending the Toolkit

### Adding a New Module

1. Create a new file in `internal/assessor/`
2. Implement the `Module` interface:

```go
type MyModule struct{}

func (m *MyModule) Name() string           { return "My Custom Check" }
func (m *MyModule) Description() string    { return "Description of what it checks" }
func (m *MyModule) TechniqueIDs() []string { return []string{"T1234"} }
func (m *MyModule) Run() AssessmentResult  { /* your checks */ }
```

3. Register in `main.go` → `getAllModules()`
4. Add technique definitions to `internal/mitre/mapping.go` if needed

---

## License & Disclaimer

This tool is provided for **authorized security assessment and educational purposes only**. The authors are not responsible for misuse. Always obtain proper authorization before running security assessments.
