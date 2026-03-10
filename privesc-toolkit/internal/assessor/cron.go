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

type ScheduledTaskModule struct{}

func (m *ScheduledTaskModule) Name() string        { return "Scheduled Task & Cron Analysis" }
func (m *ScheduledTaskModule) Description() string  { return "Analyzes cron jobs, at jobs, and systemd timers for privilege escalation (T1053)" }
func (m *ScheduledTaskModule) TechniqueIDs() []string { return []string{"T1053", "T1053.002", "T1053.003", "T1053.006"} }

func (m *ScheduledTaskModule) Run() AssessmentResult {
	start := time.Now()
	result := AssessmentResult{ModuleName: m.Name()}

	m.checkSystemCrontabs(&result)
	m.checkUserCrontabs(&result)
	m.checkCronDirectories(&result)
	m.checkAtJobs(&result)
	m.checkSystemdTimers(&result)
	m.checkCronAccessControl(&result)

	result.Duration = time.Since(start).String()
	return result
}

func (m *ScheduledTaskModule) checkSystemCrontabs(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1053.003"]

	crontab := "/etc/crontab"
	content, err := os.ReadFile(crontab)
	if err != nil {
		return
	}

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for scripts run as root
		if strings.Contains(line, "root") {
			fields := strings.Fields(line)
			if len(fields) >= 7 {
				cmd := strings.Join(fields[6:], " ")
				// Check if the script/binary is writable
				scriptPath := fields[6]
				if isWritableByCurrentUser(scriptPath) {
					result.Findings = append(result.Findings, mitre.Finding{
						Technique:   tech,
						Detail:      fmt.Sprintf("Writable cron job running as root: %s (line %d)", crontab, i+1),
						Evidence:    fmt.Sprintf("Command: %s | Script %s is writable", cmd, scriptPath),
						Remediation: fmt.Sprintf("Fix permissions on %s: chmod 755 and chown root:root", scriptPath),
						RiskScore:   95,
					})
				}
			}
		}
	}

	// Check crontab file permissions
	info, err := os.Stat(crontab)
	if err == nil && info.Mode()&0002 != 0 {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique:   tech,
			Detail:      "World-writable /etc/crontab",
			Evidence:    fmt.Sprintf("Permissions: %s", info.Mode().String()),
			Remediation: "chmod 0644 /etc/crontab",
			RiskScore:   95,
		})
	}
}

func (m *ScheduledTaskModule) checkUserCrontabs(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1053.003"]

	// Check for user crontabs
	spoolDirs := []string{"/var/spool/cron", "/var/spool/cron/crontabs"}
	for _, dir := range spoolDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			fp := filepath.Join(dir, e.Name())
			info, _ := os.Stat(fp)
			if info != nil && (info.Mode()&0066 != 0) {
				result.Findings = append(result.Findings, mitre.Finding{
					Technique: mitre.Technique{
						ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
						SubName: tech.SubName, Severity: "HIGH", Tactic: tech.Tactic,
					},
					Detail:      fmt.Sprintf("Accessible user crontab: %s", fp),
					Evidence:    fmt.Sprintf("Permissions: %s | Owner: %s", info.Mode().String(), e.Name()),
					Remediation: fmt.Sprintf("Fix permissions: chmod 600 %s", fp),
					RiskScore:   75,
				})
			}
		}
	}
}

func (m *ScheduledTaskModule) checkCronDirectories(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1053.003"]

	cronDirs := []string{
		"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
		"/etc/cron.weekly", "/etc/cron.monthly",
	}

	for _, dir := range cronDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		// Check directory permissions
		dirInfo, _ := os.Stat(dir)
		if dirInfo != nil && dirInfo.Mode()&0002 != 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique:   tech,
				Detail:      fmt.Sprintf("World-writable cron directory: %s", dir),
				Evidence:    fmt.Sprintf("Permissions: %s", dirInfo.Mode().String()),
				Remediation: fmt.Sprintf("chmod 0755 %s", dir),
				RiskScore:   90,
			})
		}

		for _, e := range entries {
			fp := filepath.Join(dir, e.Name())
			info, err := os.Stat(fp)
			if err != nil {
				continue
			}
			if info.Mode()&0002 != 0 {
				result.Findings = append(result.Findings, mitre.Finding{
					Technique:   tech,
					Detail:      fmt.Sprintf("World-writable cron script: %s", fp),
					Evidence:    fmt.Sprintf("Permissions: %s", info.Mode().String()),
					Remediation: fmt.Sprintf("chmod 0755 %s", fp),
					RiskScore:   90,
				})
			}

			// Check if scripts reference writable paths
			content, err := os.ReadFile(fp)
			if err != nil {
				continue
			}
			m.checkScriptForWritablePaths(result, tech, fp, string(content))
		}
	}
}

func (m *ScheduledTaskModule) checkScriptForWritablePaths(result *AssessmentResult, tech mitre.Technique, scriptPath, content string) {
	// Check for wildcard injection possibilities
	if strings.Contains(content, "*") {
		lines := strings.Split(content, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			if strings.Contains(line, "*") && (strings.Contains(line, "tar") ||
				strings.Contains(line, "rsync") || strings.Contains(line, "chown") ||
				strings.Contains(line, "chmod")) {
				result.Findings = append(result.Findings, mitre.Finding{
					Technique: tech,
					Detail:    fmt.Sprintf("Potential wildcard injection in cron script: %s", scriptPath),
					Evidence:  fmt.Sprintf("Line: %s", truncate(line, 200)),
					Remediation: "Avoid using wildcards in cron scripts, use explicit file lists instead",
					RiskScore: 80,
				})
			}
		}
	}

	// Check for relative paths in cron scripts
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" || strings.HasPrefix(line, "PATH=") {
			continue
		}
		// Simple check for commands without absolute paths
		fields := strings.Fields(line)
		if len(fields) > 0 && !strings.HasPrefix(fields[0], "/") && !strings.HasPrefix(fields[0], "$") &&
			!strings.Contains(fields[0], "=") && len(fields[0]) > 1 {
			// Could be a PATH hijacking vector
		}
	}
}

func (m *ScheduledTaskModule) checkAtJobs(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1053.002"]

	// Check at jobs
	out, err := exec.Command("atq").CombinedOutput()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique: mitre.Technique{
				ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
				SubName: tech.SubName, Severity: "MEDIUM", Tactic: tech.Tactic,
			},
			Detail:    "Active at jobs detected",
			Evidence:  truncate(string(out), 500),
			Remediation: "Review pending at jobs for unauthorized entries",
			RiskScore: 40,
		})
	}

	// Check at.allow / at.deny
	for _, f := range []string{"/etc/at.allow", "/etc/at.deny"} {
		if _, err := os.Stat(f); err == nil {
			info, _ := os.Stat(f)
			if info != nil && info.Mode()&0022 != 0 {
				result.Findings = append(result.Findings, mitre.Finding{
					Technique: mitre.Technique{
						ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
						SubName: tech.SubName, Severity: "MEDIUM", Tactic: tech.Tactic,
					},
					Detail:      fmt.Sprintf("Writable at access control file: %s", f),
					Evidence:    fmt.Sprintf("Permissions: %s", info.Mode().String()),
					Remediation: fmt.Sprintf("chmod 0640 %s", f),
					RiskScore:   60,
				})
			}
		}
	}
}

func (m *ScheduledTaskModule) checkSystemdTimers(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1053.006"]

	out, err := exec.Command("systemctl", "list-timers", "--all", "--no-pager").CombinedOutput()
	if err != nil {
		return
	}

	result.Findings = append(result.Findings, mitre.Finding{
		Technique: mitre.Technique{
			ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
			SubName: tech.SubName, Severity: "INFO", Tactic: tech.Tactic,
		},
		Detail:    "Systemd timers enumerated",
		Evidence:  truncate(string(out), 800),
		RiskScore: 10,
	})

	// Check timer unit files in writable locations
	timerDirs := []string{
		"/etc/systemd/system", "/usr/lib/systemd/system",
		"/run/systemd/system",
	}
	for _, dir := range timerDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".timer") {
				continue
			}
			fp := filepath.Join(dir, e.Name())
			info, err := os.Stat(fp)
			if err != nil {
				continue
			}
			if info.Mode()&0002 != 0 {
				result.Findings = append(result.Findings, mitre.Finding{
					Technique: tech,
					Detail:    fmt.Sprintf("World-writable systemd timer: %s", fp),
					Evidence:  fmt.Sprintf("Permissions: %s", info.Mode().String()),
					Remediation: fmt.Sprintf("chmod 0644 %s", fp),
					RiskScore: 85,
				})
			}
		}
	}
}

func (m *ScheduledTaskModule) checkCronAccessControl(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1053.003"]

	// If neither cron.allow nor cron.deny exists, all users can use cron
	allowExists := fileExists("/etc/cron.allow")
	denyExists := fileExists("/etc/cron.deny")

	if !allowExists && !denyExists {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique: mitre.Technique{
				ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
				SubName: tech.SubName, Severity: "MEDIUM", Tactic: tech.Tactic,
			},
			Detail:      "No cron access control files found",
			Evidence:    "Neither /etc/cron.allow nor /etc/cron.deny exists - all users can schedule cron jobs",
			Remediation: "Create /etc/cron.allow with authorized users only",
			RiskScore:   50,
		})
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
