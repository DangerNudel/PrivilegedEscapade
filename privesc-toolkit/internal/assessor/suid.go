package assessor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/privesc-toolkit/internal/mitre"
)

// Known binaries that can be abused for privilege escalation when SUID is set
var dangerousSUIDBinaries = map[string]string{
	"nmap":       "nmap --interactive can spawn a root shell",
	"vim":        "vim can spawn a root shell via :!/bin/sh",
	"find":       "find can execute commands as root via -exec",
	"bash":       "bash -p preserves effective UID for root shell",
	"less":       "less can spawn a root shell via !/bin/sh",
	"more":       "more can spawn a root shell via !/bin/sh",
	"nano":       "nano can be used to edit sensitive files as root",
	"cp":         "cp can overwrite critical files like /etc/passwd",
	"mv":         "mv can replace binaries and config files",
	"python":     "python can execute arbitrary code as root",
	"python2":    "python2 can execute arbitrary code as root",
	"python3":    "python3 can execute arbitrary code as root",
	"perl":       "perl can execute arbitrary code as root",
	"ruby":       "ruby can execute arbitrary code as root",
	"lua":        "lua can execute arbitrary code as root",
	"awk":        "awk can spawn a root shell",
	"gawk":       "gawk can spawn a root shell",
	"curl":       "curl can overwrite files with -o as root",
	"wget":       "wget can overwrite files with -O as root",
	"nc":         "netcat can create a reverse shell as root",
	"netcat":     "netcat can create a reverse shell as root",
	"socat":      "socat can create a reverse shell as root",
	"gcc":        "gcc can compile and execute code as root",
	"env":        "env can bypass restricted environments",
	"strace":     "strace can attach to root processes",
	"ltrace":     "ltrace can attach to root processes",
	"gdb":        "gdb can attach to root processes and inject code",
	"docker":     "docker can mount host filesystem for root access",
	"systemctl":  "systemctl can create root services",
	"journalctl": "journalctl can spawn a root shell via !/bin/sh",
	"ed":         "ed can edit files as root",
	"emacs":      "emacs can spawn a root shell",
	"man":        "man can spawn a root shell via !/bin/sh",
	"ftp":        "ftp can spawn a root shell via !/bin/sh",
	"scp":        "scp can copy files with root privileges",
	"ssh":        "ssh can spawn processes with proxy commands as root",
	"zip":        "zip -T can execute commands as root",
	"unzip":      "unzip can overwrite files as root",
	"tar":        "tar can execute commands via --checkpoint-action",
	"mount":      "mount can be abused to mount attacker-controlled filesystems",
	"pkexec":     "pkexec may have known privilege escalation vulnerabilities (CVE-2021-4034)",
	"doas":       "doas can execute commands as another user",
	"aria2c":     "aria2c can overwrite files as root",
	"tclsh":      "tclsh can execute arbitrary code as root",
	"php":        "php can execute arbitrary code as root",
	"node":       "node can execute arbitrary code as root",
	"tcpdump":    "tcpdump can execute commands via -z flag",
	"taskset":    "taskset can execute arbitrary commands as root",
	"time":       "time can execute arbitrary commands as root",
	"timeout":    "timeout can execute arbitrary commands as root",
	"screen":     "screen may have local privilege escalation vectors",
}

type SUIDBinaryModule struct{}

func (m *SUIDBinaryModule) Name() string        { return "SUID/SGID Binary Analysis" }
func (m *SUIDBinaryModule) Description() string  { return "Scans for SUID/SGID binaries that may be abused for privilege escalation (T1548.001)" }
func (m *SUIDBinaryModule) TechniqueIDs() []string { return []string{"T1548", "T1548.001"} }

func (m *SUIDBinaryModule) Run() AssessmentResult {
	start := time.Now()
	result := AssessmentResult{ModuleName: m.Name()}

	tech := mitre.PrivEscTechniques["T1548.001"]

	// Find SUID binaries
	suidFiles := findSUIDBinaries()
	for _, f := range suidFiles {
		base := filepath.Base(f)
		if desc, ok := dangerousSUIDBinaries[base]; ok {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique:   tech,
				Detail:      fmt.Sprintf("Dangerous SUID binary found: %s", f),
				Evidence:    desc,
				Remediation: fmt.Sprintf("Remove SUID bit: chmod u-s %s (if not required)", f),
				RiskScore:   mitre.SeverityScore("CRITICAL"),
			})
		}
	}

	// Find SGID binaries
	sgidFiles := findSGIDBinaries()
	for _, f := range sgidFiles {
		base := filepath.Base(f)
		if desc, ok := dangerousSUIDBinaries[base]; ok {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: mitre.Technique{
					ID: "T1548", SubID: "T1548.001", Name: "Abuse Elevation Control Mechanism",
					SubName: "Setuid and Setgid", Severity: "HIGH",
					Tactic: "Privilege Escalation",
				},
				Detail:      fmt.Sprintf("Dangerous SGID binary found: %s", f),
				Evidence:    desc,
				Remediation: fmt.Sprintf("Remove SGID bit: chmod g-s %s (if not required)", f),
				RiskScore:   mitre.SeverityScore("HIGH"),
			})
		}
	}

	// Check for unusual SUID in user-writable dirs
	for _, f := range suidFiles {
		dir := filepath.Dir(f)
		if isWritableByCurrentUser(dir) {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: tech,
				Detail:    fmt.Sprintf("SUID binary in writable directory: %s", f),
				Evidence:  fmt.Sprintf("Directory %s is writable - binary could be replaced", dir),
				Remediation: "Move SUID binary to a non-writable directory or restrict directory permissions",
				RiskScore: 90,
			})
		}
	}

	// Report total counts as informational
	if len(suidFiles) > 0 || len(sgidFiles) > 0 {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique: mitre.Technique{
				ID: "T1548", SubID: "T1548.001", Name: "Abuse Elevation Control Mechanism",
				SubName: "Setuid and Setgid", Severity: "INFO",
				Tactic: "Privilege Escalation",
			},
			Detail:    fmt.Sprintf("Total: %d SUID binaries, %d SGID binaries found on system", len(suidFiles), len(sgidFiles)),
			Evidence:  "Full enumeration complete",
			RiskScore: 10,
		})
	}

	result.Duration = time.Since(start).String()
	return result
}

func findSUIDBinaries() []string {
	out, err := exec.Command("find", "/", "-perm", "-4000", "-type", "f", "-readable").CombinedOutput()
	if err != nil {
		// Try common paths if full scan fails
		out, _ = exec.Command("find", "/usr", "/bin", "/sbin", "/opt", "-perm", "-4000", "-type", "f").CombinedOutput()
	}
	return parseFileList(string(out))
}

func findSGIDBinaries() []string {
	out, err := exec.Command("find", "/", "-perm", "-2000", "-type", "f", "-readable").CombinedOutput()
	if err != nil {
		out, _ = exec.Command("find", "/usr", "/bin", "/sbin", "/opt", "-perm", "-2000", "-type", "f").CombinedOutput()
	}
	return parseFileList(string(out))
}

func parseFileList(output string) []string {
	var files []string
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.Contains(line, "Permission denied") && !strings.Contains(line, "No such file") {
			files = append(files, line)
		}
	}
	return files
}

func isWritableByCurrentUser(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	mode := info.Mode()
	return mode&0002 != 0 || mode&0020 != 0
}
