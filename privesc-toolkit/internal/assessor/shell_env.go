package assessor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/privesc-toolkit/internal/mitre"
)

type ShellEnvModule struct{}

func (m *ShellEnvModule) Name() string        { return "Shell & Event-Triggered Execution Analysis" }
func (m *ShellEnvModule) Description() string  { return "Checks shell configs, profile scripts, autostart entries, and event hooks (T1546, T1547)" }
func (m *ShellEnvModule) TechniqueIDs() []string {
	return []string{"T1546", "T1546.004", "T1546.005", "T1547", "T1547.006", "T1547.013", "T1037.004"}
}

func (m *ShellEnvModule) Run() AssessmentResult {
	start := time.Now()
	result := AssessmentResult{ModuleName: m.Name()}

	m.checkGlobalShellConfigs(&result)
	m.checkUserShellConfigs(&result)
	m.checkProfileScripts(&result)
	m.checkXDGAutostart(&result)
	m.checkEnvironmentFiles(&result)
	m.checkMotd(&result)

	result.Duration = time.Since(start).String()
	return result
}

func (m *ShellEnvModule) checkGlobalShellConfigs(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1546.004"]

	globalConfigs := []string{
		"/etc/bash.bashrc", "/etc/bashrc", "/etc/profile",
		"/etc/zsh/zshrc", "/etc/zshrc", "/etc/zsh/zprofile",
		"/etc/environment", "/etc/security/pam_env.conf",
	}

	for _, f := range globalConfigs {
		info, err := os.Stat(f)
		if err != nil {
			continue
		}
		if info.Mode()&0002 != 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique:   tech,
				Detail:      fmt.Sprintf("World-writable global shell config: %s", f),
				Evidence:    fmt.Sprintf("Permissions: %s | Code injected here runs for ALL users", info.Mode().String()),
				Remediation: fmt.Sprintf("chmod 0644 %s", f),
				RiskScore:   90,
			})
		}
		if info.Mode()&0020 != 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: mitre.Technique{
					ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
					SubName: tech.SubName, Severity: "HIGH", Tactic: tech.Tactic,
				},
				Detail:      fmt.Sprintf("Group-writable global shell config: %s", f),
				Evidence:    fmt.Sprintf("Permissions: %s", info.Mode().String()),
				Remediation: fmt.Sprintf("chmod 0644 %s", f),
				RiskScore:   75,
			})
		}
	}
}

func (m *ShellEnvModule) checkUserShellConfigs(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1546.004"]

	home, _ := os.UserHomeDir()
	if home == "" {
		return
	}

	userConfigs := []string{
		".bashrc", ".bash_profile", ".bash_login", ".profile",
		".zshrc", ".zprofile", ".zlogin", ".zshenv",
		".cshrc", ".tcshrc", ".login",
	}

	for _, f := range userConfigs {
		fp := filepath.Join(home, f)
		info, err := os.Stat(fp)
		if err != nil {
			continue
		}
		if info.Mode()&0002 != 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: mitre.Technique{
					ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
					SubName: tech.SubName, Severity: "HIGH", Tactic: tech.Tactic,
				},
				Detail:      fmt.Sprintf("World-writable user shell config: %s", fp),
				Evidence:    fmt.Sprintf("Permissions: %s | Backdoor code executes on login", info.Mode().String()),
				Remediation: fmt.Sprintf("chmod 0644 %s", fp),
				RiskScore:   75,
			})
		}

		// Check for suspicious content in shell configs
		content, err := os.ReadFile(fp)
		if err != nil {
			continue
		}
		m.checkSuspiciousShellContent(result, fp, string(content))
	}

	// Also check root's configs if accessible
	rootConfigs := []string{"/root/.bashrc", "/root/.profile", "/root/.bash_profile"}
	for _, f := range rootConfigs {
		info, err := os.Stat(f)
		if err != nil {
			continue
		}
		if info.Mode()&0022 != 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique:   tech,
				Detail:      fmt.Sprintf("Writable root shell config: %s", f),
				Evidence:    fmt.Sprintf("Permissions: %s | Backdoor executes when root opens a shell", info.Mode().String()),
				Remediation: fmt.Sprintf("chmod 0600 %s", f),
				RiskScore:   85,
			})
		}
	}
}

func (m *ShellEnvModule) checkSuspiciousShellContent(result *AssessmentResult, filepath, content string) {
	tech := mitre.PrivEscTechniques["T1546.004"]

	suspicious := []struct {
		pattern string
		desc    string
	}{
		{"nc -", "Netcat command found - potential reverse shell"},
		{"ncat ", "Ncat command found - potential reverse shell"},
		{"/dev/tcp/", "Bash network redirection - potential reverse shell"},
		{"curl | sh", "Piped download to shell execution"},
		{"curl | bash", "Piped download to shell execution"},
		{"wget -O- | sh", "Piped download to shell execution"},
		{"base64 -d", "Base64 decode - potential obfuscated payload"},
		{"eval $(", "Dynamic code evaluation - potential code injection"},
		{"alias sudo=", "Sudo alias - potential credential capture"},
		{"alias su=", "Su alias - potential credential capture"},
		{"LD_PRELOAD=", "LD_PRELOAD set in shell config - dynamic linker hijacking"},
		{"LD_LIBRARY_PATH=", "LD_LIBRARY_PATH in shell config - library hijacking"},
		{"keylogger", "Keylogger reference found"},
		{"chmod +s", "SUID bit being set in shell config"},
		{"chmod u+s", "SUID bit being set in shell config"},
	}

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		for _, s := range suspicious {
			if strings.Contains(trimmed, s.pattern) {
				result.Findings = append(result.Findings, mitre.Finding{
					Technique: mitre.Technique{
						ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
						SubName: tech.SubName, Severity: "HIGH", Tactic: tech.Tactic,
					},
					Detail:      fmt.Sprintf("Suspicious content in %s", filepath),
					Evidence:    fmt.Sprintf("Pattern: %s | %s", s.pattern, s.desc),
					Remediation: fmt.Sprintf("Review and remove suspicious entries from %s", filepath),
					RiskScore:   70,
				})
				break
			}
		}
	}

	// Check for trap commands (T1546.005)
	if strings.Contains(content, "trap ") {
		for _, line := range lines {
			if strings.Contains(line, "trap ") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				result.Findings = append(result.Findings, mitre.Finding{
					Technique: mitre.PrivEscTechniques["T1546.005"],
					Detail:    fmt.Sprintf("Trap command in shell config: %s", filepath),
					Evidence:  truncate(strings.TrimSpace(line), 200),
					Remediation: "Review trap commands for unauthorized signal handlers",
					RiskScore: 40,
				})
			}
		}
	}
}

func (m *ShellEnvModule) checkProfileScripts(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1037.004"]

	profileDir := "/etc/profile.d"
	entries, err := os.ReadDir(profileDir)
	if err != nil {
		return
	}

	// Check directory permissions
	dirInfo, _ := os.Stat(profileDir)
	if dirInfo != nil && dirInfo.Mode()&0002 != 0 {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique: tech,
			Detail:    "World-writable /etc/profile.d/ directory",
			Evidence:  "Any user can add login scripts that execute for all users",
			Remediation: "chmod 0755 /etc/profile.d",
			RiskScore: 85,
		})
	}

	for _, e := range entries {
		fp := filepath.Join(profileDir, e.Name())
		info, err := os.Stat(fp)
		if err != nil {
			continue
		}
		if info.Mode()&0002 != 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: tech,
				Detail:    fmt.Sprintf("World-writable profile script: %s", fp),
				Evidence:  fmt.Sprintf("Permissions: %s | Executes for all users at login", info.Mode().String()),
				Remediation: fmt.Sprintf("chmod 0644 %s", fp),
				RiskScore: 80,
			})
		}
	}
}

func (m *ShellEnvModule) checkXDGAutostart(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1547.013"]

	autostartDirs := []string{
		"/etc/xdg/autostart",
	}

	home, _ := os.UserHomeDir()
	if home != "" {
		autostartDirs = append(autostartDirs, filepath.Join(home, ".config/autostart"))
	}

	for _, dir := range autostartDirs {
		info, err := os.Stat(dir)
		if err != nil {
			continue
		}
		if info.Mode()&0002 != 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: tech,
				Detail:    fmt.Sprintf("World-writable XDG autostart directory: %s", dir),
				Evidence:  "Malicious .desktop files can be added for user session persistence",
				Remediation: fmt.Sprintf("chmod 0755 %s", dir),
				RiskScore: 70,
			})
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".desktop") {
				continue
			}
			fp := filepath.Join(dir, e.Name())
			finfo, _ := os.Stat(fp)
			if finfo != nil && finfo.Mode()&0002 != 0 {
				result.Findings = append(result.Findings, mitre.Finding{
					Technique: mitre.Technique{
						ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
						SubName: tech.SubName, Severity: "MEDIUM", Tactic: tech.Tactic,
					},
					Detail:    fmt.Sprintf("Writable XDG autostart entry: %s", fp),
					Evidence:  fmt.Sprintf("Permissions: %s", finfo.Mode().String()),
					Remediation: fmt.Sprintf("chmod 0644 %s", fp),
					RiskScore: 55,
				})
			}
		}
	}
}

func (m *ShellEnvModule) checkEnvironmentFiles(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1574.006"]

	envFile := "/etc/environment"
	content, err := os.ReadFile(envFile)
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "LD_PRELOAD") || strings.Contains(line, "LD_LIBRARY_PATH") {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: tech,
				Detail:    fmt.Sprintf("Dangerous variable in /etc/environment: %s", line),
				Evidence:  "System-wide environment injection for dynamic linker hijacking",
				Remediation: "Remove LD_PRELOAD/LD_LIBRARY_PATH from /etc/environment",
				RiskScore: 85,
			})
		}
	}
}

func (m *ShellEnvModule) checkMotd(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1546.004"]

	motdDirs := []string{"/etc/update-motd.d"}
	for _, dir := range motdDirs {
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
					Technique: mitre.Technique{
						ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
						SubName: tech.SubName, Severity: "HIGH", Tactic: tech.Tactic,
					},
					Detail:    fmt.Sprintf("World-writable MOTD script: %s", fp),
					Evidence:  fmt.Sprintf("Permissions: %s | Executes as root on user login", info.Mode().String()),
					Remediation: fmt.Sprintf("chmod 0755 %s", fp),
					RiskScore: 80,
				})
			}
		}
	}
}
