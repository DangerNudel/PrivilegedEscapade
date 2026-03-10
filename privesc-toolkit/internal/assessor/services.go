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

type ServiceModule struct{}

func (m *ServiceModule) Name() string        { return "System Service & Daemon Analysis" }
func (m *ServiceModule) Description() string  { return "Analyzes systemd services and init scripts for privilege escalation (T1543)" }
func (m *ServiceModule) TechniqueIDs() []string { return []string{"T1543", "T1543.002"} }

func (m *ServiceModule) Run() AssessmentResult {
	start := time.Now()
	result := AssessmentResult{ModuleName: m.Name()}

	m.checkSystemdUnits(&result)
	m.checkInitScripts(&result)
	m.checkServiceBinaryPerms(&result)
	m.checkDBusConfig(&result)
	m.checkRCLocal(&result)

	result.Duration = time.Since(start).String()
	return result
}

func (m *ServiceModule) checkSystemdUnits(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1543.002"]

	unitDirs := []string{
		"/etc/systemd/system",
		"/usr/lib/systemd/system",
		"/usr/local/lib/systemd/system",
		"/run/systemd/system",
	}

	for _, dir := range unitDirs {
		// Check if directory itself is writable
		if isWritableByCurrentUser(dir) {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique:   tech,
				Detail:      fmt.Sprintf("Writable systemd unit directory: %s", dir),
				Evidence:    "Any user can create new systemd services in this directory",
				Remediation: fmt.Sprintf("chmod 0755 %s; chown root:root %s", dir, dir),
				RiskScore:   90,
			})
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".service") {
				continue
			}
			fp := filepath.Join(dir, e.Name())
			info, err := os.Stat(fp)
			if err != nil {
				continue
			}

			// World-writable service files
			if info.Mode()&0002 != 0 {
				result.Findings = append(result.Findings, mitre.Finding{
					Technique:   tech,
					Detail:      fmt.Sprintf("World-writable systemd service: %s", fp),
					Evidence:    fmt.Sprintf("Permissions: %s", info.Mode().String()),
					Remediation: fmt.Sprintf("chmod 0644 %s", fp),
					RiskScore:   90,
				})
			}

			// Check service content for risky configurations
			content, err := os.ReadFile(fp)
			if err != nil {
				continue
			}
			m.analyzeServiceUnit(result, tech, fp, string(content))
		}
	}
}

func (m *ServiceModule) analyzeServiceUnit(result *AssessmentResult, tech mitre.Technique, path, content string) {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check for services running as root without hardening
		if strings.HasPrefix(line, "ExecStart=") {
			execPath := strings.TrimPrefix(line, "ExecStart=")
			execPath = strings.Fields(execPath)[0]
			if strings.HasPrefix(execPath, "-") {
				execPath = execPath[1:] // Remove optional prefix
			}
			if isWritableByCurrentUser(execPath) {
				result.Findings = append(result.Findings, mitre.Finding{
					Technique: tech,
					Detail:    fmt.Sprintf("Writable service binary: %s in %s", execPath, filepath.Base(path)),
					Evidence:  fmt.Sprintf("ExecStart binary %s can be replaced by current user", execPath),
					Remediation: fmt.Sprintf("Fix permissions: chmod 0755 %s; chown root:root %s", execPath, execPath),
					RiskScore: 90,
				})
			}
		}

		// Check for missing security hardening
		if strings.HasPrefix(line, "User=") && strings.Contains(line, "root") {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: mitre.Technique{
					ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
					SubName: tech.SubName, Severity: "MEDIUM", Tactic: tech.Tactic,
				},
				Detail:      fmt.Sprintf("Service explicitly runs as root: %s", filepath.Base(path)),
				Evidence:    line,
				Remediation: "Consider running the service with a dedicated non-root user",
				RiskScore:   40,
			})
		}
	}
}

func (m *ServiceModule) checkInitScripts(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1037.004"]

	initDirs := []string{"/etc/init.d", "/etc/init"}
	for _, dir := range initDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			fp := filepath.Join(dir, e.Name())
			info, err := os.Stat(fp)
			if err != nil {
				continue
			}
			if info.Mode()&0002 != 0 {
				result.Findings = append(result.Findings, mitre.Finding{
					Technique: tech,
					Detail:    fmt.Sprintf("World-writable init script: %s", fp),
					Evidence:  fmt.Sprintf("Permissions: %s", info.Mode().String()),
					Remediation: fmt.Sprintf("chmod 0755 %s", fp),
					RiskScore: 85,
				})
			}
		}
	}
}

func (m *ServiceModule) checkServiceBinaryPerms(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1574.010"]

	out, err := exec.Command("systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend").CombinedOutput()
	if err != nil {
		return
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		svcName := fields[0]

		// Get ExecStart path
		showOut, err := exec.Command("systemctl", "show", "-p", "ExecStart", svcName).CombinedOutput()
		if err != nil {
			continue
		}
		output := string(showOut)
		// Parse path from ExecStart output
		if strings.Contains(output, "path=") {
			parts := strings.Split(output, "path=")
			if len(parts) > 1 {
				binPath := strings.Split(parts[1], " ")[0]
				binPath = strings.Trim(binPath, "; \n{}")
				if binPath != "" && isWritableByCurrentUser(binPath) {
					result.Findings = append(result.Findings, mitre.Finding{
						Technique: tech,
						Detail:    fmt.Sprintf("Running service has writable binary: %s -> %s", svcName, binPath),
						Evidence:  "Service binary can be replaced to execute arbitrary code as root on next restart",
						Remediation: fmt.Sprintf("chmod 0755 %s; chown root:root %s", binPath, binPath),
						RiskScore: 85,
					})
				}
			}
		}
	}
}

func (m *ServiceModule) checkDBusConfig(result *AssessmentResult) {
	dbusDir := "/etc/dbus-1/system.d"
	entries, err := os.ReadDir(dbusDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		fp := filepath.Join(dbusDir, e.Name())
		info, err := os.Stat(fp)
		if err != nil {
			continue
		}
		if info.Mode()&0002 != 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: mitre.Technique{
					ID: "T1543", Name: "Create or Modify System Process",
					Severity: "HIGH", Tactic: "Privilege Escalation",
				},
				Detail:      fmt.Sprintf("Writable D-Bus system config: %s", fp),
				Evidence:    fmt.Sprintf("Permissions: %s", info.Mode().String()),
				Remediation: fmt.Sprintf("chmod 0644 %s", fp),
				RiskScore:   75,
			})
		}
	}
}

func (m *ServiceModule) checkRCLocal(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1037.004"]

	rcLocal := "/etc/rc.local"
	info, err := os.Stat(rcLocal)
	if err != nil {
		return
	}

	if info.Mode()&0002 != 0 {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique: tech,
			Detail:    "World-writable /etc/rc.local",
			Evidence:  fmt.Sprintf("Permissions: %s - commands will execute as root at boot", info.Mode().String()),
			Remediation: "chmod 0755 /etc/rc.local; chown root:root /etc/rc.local",
			RiskScore: 90,
		})
	}

	if info.Mode()&0111 != 0 {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique: mitre.Technique{
				ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
				SubName: tech.SubName, Severity: "INFO", Tactic: tech.Tactic,
			},
			Detail:    "/etc/rc.local is executable and will run at boot",
			Evidence:  "Review contents for unauthorized commands",
			RiskScore: 20,
		})
	}
}
