package assessor

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"

	"github.com/privesc-toolkit/internal/mitre"
)

type AccountModule struct{}

func (m *AccountModule) Name() string        { return "Account & Credential Analysis" }
func (m *AccountModule) Description() string  { return "Analyzes user accounts, credential storage, and authentication vectors (T1078)" }
func (m *AccountModule) TechniqueIDs() []string { return []string{"T1078", "T1078.001", "T1078.003"} }

func (m *AccountModule) Run() AssessmentResult {
	start := time.Now()
	result := AssessmentResult{ModuleName: m.Name()}

	m.checkCurrentUser(&result)
	m.checkPasswdFile(&result)
	m.checkShadowAccess(&result)
	m.checkSSHKeys(&result)
	m.checkCredentialFiles(&result)
	m.checkHistoryFiles(&result)
	m.checkHomeDirPerms(&result)
	m.checkPAMConfig(&result)

	result.Duration = time.Since(start).String()
	return result
}

func (m *AccountModule) checkCurrentUser(result *AssessmentResult) {
	u, err := user.Current()
	if err != nil {
		return
	}

	out, _ := exec.Command("id").CombinedOutput()

	result.Findings = append(result.Findings, mitre.Finding{
		Technique: mitre.Technique{
			ID: "T1078", Name: "Valid Accounts", Severity: "INFO",
			Tactic: "Privilege Escalation",
		},
		Detail:    fmt.Sprintf("Current user: %s (UID: %s, GID: %s)", u.Username, u.Uid, u.Gid),
		Evidence:  strings.TrimSpace(string(out)),
		RiskScore: 10,
	})

	if u.Uid == "0" {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique: mitre.Technique{
				ID: "T1078", Name: "Valid Accounts", Severity: "INFO",
				Tactic: "Privilege Escalation",
			},
			Detail:    "Already running as root (UID 0)",
			Evidence:  "No privilege escalation needed - already at maximum privilege level",
			RiskScore: 10,
		})
	}
}

func (m *AccountModule) checkPasswdFile(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1078.003"]

	// Check if /etc/passwd is writable
	info, err := os.Stat("/etc/passwd")
	if err == nil && info.Mode()&0002 != 0 {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique:   tech,
			Detail:      "World-writable /etc/passwd",
			Evidence:    fmt.Sprintf("Permissions: %s | Can add new root-level user", info.Mode().String()),
			Remediation: "chmod 0644 /etc/passwd",
			RiskScore:   95,
		})
	}

	content, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(content), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}

		// Check for UID 0 accounts other than root
		if fields[2] == "0" && fields[0] != "root" {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: tech,
				Detail:    fmt.Sprintf("Non-root account with UID 0: %s", fields[0]),
				Evidence:  fmt.Sprintf("User %s has UID 0 (root equivalent)", fields[0]),
				Remediation: "Investigate and remove unauthorized UID 0 accounts",
				RiskScore: 95,
			})
		}

		// Check for password hashes in passwd (not using shadow)
		if len(fields[1]) > 1 && fields[1] != "x" && fields[1] != "*" && fields[1] != "!" {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: tech,
				Detail:    fmt.Sprintf("Password hash in /etc/passwd for user: %s", fields[0]),
				Evidence:  "Password stored in world-readable file instead of /etc/shadow",
				Remediation: "Move password to /etc/shadow using pwconv",
				RiskScore: 85,
			})
		}

		// Check for empty passwords
		if fields[1] == "" {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: mitre.PrivEscTechniques["T1078.001"],
				Detail:    fmt.Sprintf("Empty password for user: %s", fields[0]),
				Evidence:  "Account has no password set - anyone can authenticate",
				Remediation: fmt.Sprintf("Set password: passwd %s or lock account: passwd -l %s", fields[0], fields[0]),
				RiskScore: 90,
			})
		}

		// Check for users with interactive shells
		shell := fields[6]
		if (shell == "/bin/bash" || shell == "/bin/sh" || shell == "/bin/zsh") &&
			fields[0] != "root" && fields[2] != "65534" {
			// Normal finding, just enumeration
		}
	}
}

func (m *AccountModule) checkShadowAccess(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1078.003"]

	shadow := "/etc/shadow"
	info, err := os.Stat(shadow)
	if err != nil {
		return
	}

	// Check if readable by current user
	if content, err := os.ReadFile(shadow); err == nil {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique:   tech,
			Detail:      "Current user can read /etc/shadow",
			Evidence:    fmt.Sprintf("Permissions: %s | Password hashes are exposed", info.Mode().String()),
			Remediation: "chmod 0640 /etc/shadow; chown root:shadow /etc/shadow",
			RiskScore:   90,
		})

		// Check for weak/empty hashes
		for _, line := range strings.Split(string(content), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) < 2 || fields[0] == "" {
				continue
			}
			hash := fields[1]
			if hash == "" || hash == "!" || hash == "*" || hash == "!!" {
				continue
			}
			if !strings.HasPrefix(hash, "$") {
				result.Findings = append(result.Findings, mitre.Finding{
					Technique: tech,
					Detail:    fmt.Sprintf("Weak or legacy password hash for user: %s", fields[0]),
					Evidence:  "Password may use DES or other weak hashing algorithm",
					Remediation: fmt.Sprintf("Force password change for %s with a modern algorithm", fields[0]),
					RiskScore: 70,
				})
			}
		}
	}
}

func (m *AccountModule) checkSSHKeys(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1078.003"]

	// Check root's SSH keys
	rootSSH := "/root/.ssh"
	if info, err := os.Stat(rootSSH); err == nil {
		if info.Mode()&0077 != 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: tech,
				Detail:    "Root SSH directory has overly permissive permissions",
				Evidence:  fmt.Sprintf("%s permissions: %s", rootSSH, info.Mode().String()),
				Remediation: "chmod 0700 /root/.ssh",
				RiskScore: 70,
			})
		}
	}

	// Check for accessible SSH keys
	sshLocations := []string{
		"/root/.ssh/id_rsa", "/root/.ssh/id_ed25519", "/root/.ssh/id_ecdsa",
		"/root/.ssh/authorized_keys",
	}
	for _, loc := range sshLocations {
		if content, err := os.ReadFile(loc); err == nil {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique:   tech,
				Detail:      fmt.Sprintf("Accessible root SSH file: %s", loc),
				Evidence:    fmt.Sprintf("File size: %d bytes | Can be used for lateral movement or persistence", len(content)),
				Remediation: fmt.Sprintf("Restrict permissions: chmod 0600 %s", loc),
				RiskScore:   85,
			})
		}
	}

	// Check current user's SSH config
	home, _ := os.UserHomeDir()
	if home != "" {
		authKeys := home + "/.ssh/authorized_keys"
		if info, err := os.Stat(authKeys); err == nil && info.Mode()&0022 != 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: mitre.Technique{
					ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
					SubName: tech.SubName, Severity: "HIGH", Tactic: tech.Tactic,
				},
				Detail:      "Writable authorized_keys file",
				Evidence:    fmt.Sprintf("Permissions: %s | Attacker can add their own SSH key", info.Mode().String()),
				Remediation: "chmod 0600 ~/.ssh/authorized_keys",
				RiskScore:   80,
			})
		}
	}
}

func (m *AccountModule) checkCredentialFiles(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1078"]

	credFiles := []struct {
		path string
		desc string
	}{
		{"/etc/mysql/my.cnf", "MySQL configuration (may contain credentials)"},
		{"/var/lib/mysql/mysql/user.MYD", "MySQL user database"},
		{"/etc/postgresql/*/main/pg_hba.conf", "PostgreSQL auth config"},
		{"/etc/redis/redis.conf", "Redis configuration"},
		{"/etc/mongod.conf", "MongoDB configuration"},
		{"/etc/openvpn/*.conf", "OpenVPN configuration"},
		{"/etc/ppp/chap-secrets", "PPP CHAP secrets"},
		{"/etc/inetd.conf", "Inetd configuration"},
		{"/etc/xinetd.conf", "Xinetd configuration"},
		{"/etc/fstab", "Filesystem table (may contain credentials for CIFS/NFS mounts)"},
		{"/proc/net/fib_trie", "Network routing information"},
	}

	for _, cf := range credFiles {
		if _, err := os.ReadFile(cf.path); err == nil {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: mitre.Technique{
					ID: tech.ID, Name: tech.Name, Severity: "MEDIUM",
					Tactic: tech.Tactic,
				},
				Detail:      fmt.Sprintf("Readable sensitive file: %s", cf.path),
				Evidence:    cf.desc,
				Remediation: fmt.Sprintf("Restrict access to %s", cf.path),
				RiskScore:   50,
			})
		}
	}

	// Search for common credential files in home directories
	home, _ := os.UserHomeDir()
	if home != "" {
		credPatterns := []string{
			".bash_history", ".mysql_history", ".psql_history",
			".pgpass", ".my.cnf", ".netrc", ".gnupg",
			".aws/credentials", ".azure/accessTokens.json",
			".config/gcloud/credentials.db",
			".kube/config", ".docker/config.json",
		}
		for _, pat := range credPatterns {
			fp := home + "/" + pat
			if _, err := os.Stat(fp); err == nil {
				result.Findings = append(result.Findings, mitre.Finding{
					Technique: mitre.Technique{
						ID: tech.ID, Name: tech.Name, Severity: "MEDIUM",
						Tactic: tech.Tactic,
					},
					Detail:    fmt.Sprintf("Credential/config file found: %s", fp),
					Evidence:  "May contain credentials, tokens, or sensitive configuration",
					Remediation: fmt.Sprintf("Review and restrict permissions on %s", fp),
					RiskScore: 45,
				})
			}
		}
	}
}

func (m *AccountModule) checkHistoryFiles(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1078"]

	histFiles := []string{
		"/root/.bash_history", "/root/.zsh_history",
	}
	for _, f := range histFiles {
		if content, err := os.ReadFile(f); err == nil && len(content) > 0 {
			// Check for passwords in history
			for _, line := range strings.Split(string(content), "\n") {
				lower := strings.ToLower(line)
				if strings.Contains(lower, "password") || strings.Contains(lower, "passwd") ||
					strings.Contains(lower, "secret") || strings.Contains(lower, "token") ||
					strings.Contains(lower, "mysql -u") || strings.Contains(lower, "psql -U") {
					result.Findings = append(result.Findings, mitre.Finding{
						Technique: mitre.Technique{
							ID: tech.ID, Name: tech.Name, Severity: "HIGH",
							Tactic: tech.Tactic,
						},
						Detail:      fmt.Sprintf("Potential credentials in history file: %s", f),
						Evidence:    "History file may contain passwords or tokens entered on command line",
						Remediation: fmt.Sprintf("Clear history: > %s; Set HISTSIZE=0 in profile", f),
						RiskScore:   70,
					})
					break
				}
			}
		}
	}
}

func (m *AccountModule) checkHomeDirPerms(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1078.003"]

	entries, err := os.ReadDir("/home")
	if err != nil {
		return
	}
	for _, e := range entries {
		fp := "/home/" + e.Name()
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
				Detail:      fmt.Sprintf("World-writable home directory: %s", fp),
				Evidence:    fmt.Sprintf("Permissions: %s | Can plant files (e.g., .bashrc, SSH keys)", info.Mode().String()),
				Remediation: fmt.Sprintf("chmod 0750 %s", fp),
				RiskScore:   75,
			})
		}
		if info.Mode()&0044 != 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: mitre.Technique{
					ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
					SubName: tech.SubName, Severity: "LOW", Tactic: tech.Tactic,
				},
				Detail:      fmt.Sprintf("World/group-readable home directory: %s", fp),
				Evidence:    fmt.Sprintf("Permissions: %s", info.Mode().String()),
				Remediation: fmt.Sprintf("chmod 0750 %s", fp),
				RiskScore:   30,
			})
		}
	}
}

func (m *AccountModule) checkPAMConfig(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1548"]

	pamDir := "/etc/pam.d"
	entries, err := os.ReadDir(pamDir)
	if err != nil {
		return
	}

	for _, e := range entries {
		fp := pamDir + "/" + e.Name()
		info, err := os.Stat(fp)
		if err != nil {
			continue
		}
		if info.Mode()&0002 != 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: mitre.Technique{
					ID: tech.ID, Name: tech.Name, Severity: "CRITICAL",
					Tactic: tech.Tactic,
				},
				Detail:      fmt.Sprintf("World-writable PAM config: %s", fp),
				Evidence:    "Can modify authentication requirements for the service",
				Remediation: fmt.Sprintf("chmod 0644 %s", fp),
				RiskScore:   95,
			})
		}
	}
}
