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

type SudoModule struct{}

func (m *SudoModule) Name() string        { return "Sudo Configuration Analysis" }
func (m *SudoModule) Description() string  { return "Analyzes sudo configuration for privilege escalation vectors (T1548.003)" }
func (m *SudoModule) TechniqueIDs() []string { return []string{"T1548", "T1548.003"} }

func (m *SudoModule) Run() AssessmentResult {
	start := time.Now()
	result := AssessmentResult{ModuleName: m.Name()}

	tech := mitre.PrivEscTechniques["T1548.003"]

	// Check sudo -l output
	m.checkSudoPrivileges(&result, tech)

	// Check sudoers file permissions
	m.checkSudoersPerms(&result, tech)

	// Check for sudo version vulnerabilities
	m.checkSudoVersion(&result)

	// Check sudo timestamp configuration
	m.checkSudoTimestamp(&result, tech)

	// Check for NOPASSWD entries
	m.checkSudoersContent(&result, tech)

	// Check sudoers.d directory
	m.checkSudoersD(&result, tech)

	result.Duration = time.Since(start).String()
	return result
}

func (m *SudoModule) checkSudoPrivileges(result *AssessmentResult, tech mitre.Technique) {
	out, err := exec.Command("sudo", "-n", "-l").CombinedOutput()
	if err == nil {
		output := string(out)
		if strings.Contains(output, "(ALL") || strings.Contains(output, "(root)") {
			if strings.Contains(output, "NOPASSWD") {
				result.Findings = append(result.Findings, mitre.Finding{
					Technique:   tech,
					Detail:      "Current user has NOPASSWD sudo access",
					Evidence:    truncate(output, 500),
					Remediation: "Remove NOPASSWD from sudoers configuration; require password for all sudo commands",
					RiskScore:   95,
				})
			} else {
				result.Findings = append(result.Findings, mitre.Finding{
					Technique: mitre.Technique{
						ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
						SubName: tech.SubName, Severity: "MEDIUM", Tactic: tech.Tactic,
					},
					Detail:      "Current user has sudo access (password required)",
					Evidence:    truncate(output, 500),
					Remediation: "Review sudo privileges for least-privilege principle",
					RiskScore:   50,
				})
			}

			// Check for dangerous sudo commands
			dangerousCmds := []string{"ALL", "/bin/bash", "/bin/sh", "/usr/bin/env",
				"/usr/bin/python", "/usr/bin/perl", "/usr/bin/ruby", "/usr/bin/vi",
				"/usr/bin/vim", "/usr/bin/less", "/usr/bin/more", "/usr/bin/find",
				"/usr/bin/awk", "/usr/bin/nmap", "/usr/bin/ftp", "/usr/bin/man",
				"/usr/bin/nano", "/usr/bin/cp", "/usr/bin/mv", "/usr/bin/docker",
				"/usr/bin/systemctl", "/usr/bin/journalctl", "/usr/bin/pip",
				"env_keep+=LD_PRELOAD", "env_keep+=LD_LIBRARY_PATH"}
			for _, cmd := range dangerousCmds {
				if strings.Contains(output, cmd) {
					result.Findings = append(result.Findings, mitre.Finding{
						Technique:   tech,
						Detail:      fmt.Sprintf("Dangerous sudo command/config found: %s", cmd),
						Evidence:    fmt.Sprintf("Sudo allows execution of %s which can be used for shell escape", cmd),
						Remediation: fmt.Sprintf("Restrict sudo access: remove %s from allowed commands", cmd),
						RiskScore:   mitre.SeverityScore("HIGH"),
					})
				}
			}
		}
	}
}

func (m *SudoModule) checkSudoersPerms(result *AssessmentResult, tech mitre.Technique) {
	paths := []string{"/etc/sudoers", "/etc/sudoers.d"}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		mode := info.Mode()
		if mode&0002 != 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique:   tech,
				Detail:      fmt.Sprintf("World-writable sudoers path: %s", p),
				Evidence:    fmt.Sprintf("Permissions: %s", mode.String()),
				Remediation: fmt.Sprintf("Fix permissions: chmod 0440 %s", p),
				RiskScore:   95,
			})
		}
		if mode&0020 != 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: mitre.Technique{
					ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
					SubName: tech.SubName, Severity: "HIGH", Tactic: tech.Tactic,
				},
				Detail:      fmt.Sprintf("Group-writable sudoers path: %s", p),
				Evidence:    fmt.Sprintf("Permissions: %s Owner GID: %d", mode.String(), info.Sys()),
				Remediation: fmt.Sprintf("Fix permissions: chmod 0440 %s", p),
				RiskScore:   80,
			})
		}
	}
}

func (m *SudoModule) checkSudoVersion(result *AssessmentResult) {
	out, err := exec.Command("sudo", "--version").CombinedOutput()
	if err != nil {
		return
	}
	version := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	tech := mitre.PrivEscTechniques["T1068"]

	// Known sudo CVEs
	knownVulns := []struct {
		cve      string
		desc     string
		affected string
	}{
		{"CVE-2021-3156", "Heap-based buffer overflow in sudoedit (Baron Samedit)", "< 1.9.5p2"},
		{"CVE-2019-14287", "Sudo bypass via UID -1/4294967295", "< 1.8.28"},
		{"CVE-2019-18634", "Stack buffer overflow with pwfeedback enabled", "< 1.8.31"},
		{"CVE-2023-22809", "Sudoedit arbitrary file edit bypass", "1.8.0 - 1.9.12p1"},
		{"CVE-2023-28486", "Sudo does not escape control chars in log messages", "< 1.9.13p2"},
		{"CVE-2023-28487", "Sudo does not escape control chars in sudoreplay", "< 1.9.13p2"},
	}

	for _, v := range knownVulns {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique: tech,
			Detail:    fmt.Sprintf("Sudo version check for %s: %s", v.cve, v.desc),
			Evidence:  fmt.Sprintf("Installed: %s | Affected: %s | Manual verification required", version, v.affected),
			Remediation: fmt.Sprintf("Verify sudo version and update if vulnerable to %s", v.cve),
			RiskScore: 60,
		})
	}
}

func (m *SudoModule) checkSudoTimestamp(result *AssessmentResult, tech mitre.Technique) {
	// Check if sudo timestamps exist (cached credentials)
	stampDirs := []string{"/var/run/sudo/ts", "/var/db/sudo", "/run/sudo/ts"}
	for _, d := range stampDirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		if len(entries) > 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: mitre.Technique{
					ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
					SubName: tech.SubName, Severity: "MEDIUM", Tactic: tech.Tactic,
				},
				Detail:      fmt.Sprintf("Active sudo timestamp found in %s (%d entries)", d, len(entries)),
				Evidence:    "Cached sudo credentials may allow passwordless escalation within timeout window",
				Remediation: "Run 'sudo -k' to invalidate timestamps. Consider timestamp_timeout=0 in sudoers.",
				RiskScore:   45,
			})
		}
	}
}

func (m *SudoModule) checkSudoersContent(result *AssessmentResult, tech mitre.Technique) {
	content, err := os.ReadFile("/etc/sudoers")
	if err != nil {
		return
	}
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "NOPASSWD") {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique:   tech,
				Detail:      fmt.Sprintf("NOPASSWD entry in sudoers (line %d)", i+1),
				Evidence:    truncate(line, 200),
				Remediation: "Remove NOPASSWD directive; require authentication for all sudo commands",
				RiskScore:   80,
			})
		}
		if strings.Contains(line, "!authenticate") {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique:   tech,
				Detail:      fmt.Sprintf("Authentication bypass in sudoers (line %d)", i+1),
				Evidence:    truncate(line, 200),
				Remediation: "Remove !authenticate directive",
				RiskScore:   85,
			})
		}
		if strings.Contains(line, "env_keep") && (strings.Contains(line, "LD_PRELOAD") || strings.Contains(line, "LD_LIBRARY_PATH")) {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique:   mitre.PrivEscTechniques["T1574.006"],
				Detail:      fmt.Sprintf("Dangerous env_keep in sudoers (line %d)", i+1),
				Evidence:    truncate(line, 200),
				Remediation: "Remove LD_PRELOAD/LD_LIBRARY_PATH from env_keep - allows dynamic linker hijacking",
				RiskScore:   90,
			})
		}
	}
}

func (m *SudoModule) checkSudoersD(result *AssessmentResult, tech mitre.Technique) {
	entries, err := os.ReadDir("/etc/sudoers.d")
	if err != nil {
		return
	}
	for _, e := range entries {
		fp := filepath.Join("/etc/sudoers.d", e.Name())
		info, err := os.Stat(fp)
		if err != nil {
			continue
		}
		if info.Mode()&0022 != 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique:   tech,
				Detail:      fmt.Sprintf("Writable sudoers.d file: %s", fp),
				Evidence:    fmt.Sprintf("Permissions: %s", info.Mode().String()),
				Remediation: fmt.Sprintf("Fix permissions: chmod 0440 %s", fp),
				RiskScore:   90,
			})
		}
	}
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
