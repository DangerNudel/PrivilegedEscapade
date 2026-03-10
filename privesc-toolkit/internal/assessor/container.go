package assessor

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/privesc-toolkit/internal/mitre"
)

type ContainerModule struct{}

func (m *ContainerModule) Name() string        { return "Container Escape & Environment Analysis" }
func (m *ContainerModule) Description() string  { return "Checks for container escape vectors, Docker socket access, and environment exposure (T1611)" }
func (m *ContainerModule) TechniqueIDs() []string { return []string{"T1611"} }

func (m *ContainerModule) Run() AssessmentResult {
	start := time.Now()
	result := AssessmentResult{ModuleName: m.Name()}

	isContainer := m.detectContainer()

	m.checkDockerSocket(&result)
	m.checkDockerGroup(&result)
	m.checkPrivilegedContainer(&result, isContainer)
	m.checkMountedHostPaths(&result, isContainer)
	m.checkNamespaces(&result)
	m.checkCgroupEscape(&result, isContainer)
	m.checkKubernetes(&result)

	result.Duration = time.Since(start).String()
	return result
}

func (m *ContainerModule) detectContainer() bool {
	// Check multiple container indicators
	indicators := []string{
		"/.dockerenv",
		"/run/.containerenv",
	}
	for _, f := range indicators {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}

	// Check cgroup for container signatures
	content, err := os.ReadFile("/proc/1/cgroup")
	if err == nil {
		text := string(content)
		if strings.Contains(text, "docker") || strings.Contains(text, "lxc") ||
			strings.Contains(text, "kubepods") || strings.Contains(text, "containerd") {
			return true
		}
	}
	return false
}

func (m *ContainerModule) checkDockerSocket(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1611"]

	socketPaths := []string{"/var/run/docker.sock", "/run/docker.sock"}
	for _, sock := range socketPaths {
		info, err := os.Stat(sock)
		if err != nil {
			continue
		}

		// Check if current user can access docker socket
		f, err := os.OpenFile(sock, os.O_RDONLY, 0)
		if err == nil {
			f.Close()
			result.Findings = append(result.Findings, mitre.Finding{
				Technique:   tech,
				Detail:      fmt.Sprintf("Docker socket accessible: %s", sock),
				Evidence:    fmt.Sprintf("Permissions: %s | Docker socket access grants effective root", info.Mode().String()),
				Remediation: "Restrict Docker socket access; use rootless Docker or remove user from docker group",
				RiskScore:   95,
			})
		}
	}
}

func (m *ContainerModule) checkDockerGroup(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1611"]

	out, err := exec.Command("id").CombinedOutput()
	if err != nil {
		return
	}
	output := string(out)

	dangerousGroups := map[string]string{
		"docker":  "Docker group grants effective root via container mounting",
		"lxd":     "LXD group allows container creation with host mounting",
		"lxc":     "LXC group allows container manipulation",
		"adm":     "Adm group grants access to system logs",
		"disk":    "Disk group grants raw disk access (can read any file)",
		"shadow":  "Shadow group grants access to /etc/shadow",
		"video":   "Video group may allow framebuffer/keylogger access",
		"root":    "Root group membership may grant additional privileges",
		"sudo":    "Sudo group grants sudo access",
		"wheel":   "Wheel group grants sudo/su access",
		"staff":   "Staff group may have write access to /usr/local",
	}

	for group, desc := range dangerousGroups {
		if strings.Contains(output, "("+group+")") || strings.Contains(output, group) {
			sev := "HIGH"
			score := 75
			if group == "docker" || group == "lxd" || group == "disk" || group == "shadow" {
				sev = "CRITICAL"
				score = 90
			}
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: mitre.Technique{
					ID: tech.ID, Name: tech.Name, Severity: sev,
					Tactic: tech.Tactic,
				},
				Detail:      fmt.Sprintf("User is member of privileged group: %s", group),
				Evidence:    desc,
				Remediation: fmt.Sprintf("Remove user from %s group if not required: gpasswd -d $USER %s", group, group),
				RiskScore:   score,
			})
		}
	}
}

func (m *ContainerModule) checkPrivilegedContainer(result *AssessmentResult, isContainer bool) {
	if !isContainer {
		return
	}
	tech := mitre.PrivEscTechniques["T1611"]

	// Check if running in privileged mode
	content, err := os.ReadFile("/proc/1/status")
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			capHex := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			// 0000003fffffffff = all capabilities = privileged
			if capHex == "0000003fffffffff" || capHex == "000001ffffffffff" || capHex == "000000ffffffffff" {
				result.Findings = append(result.Findings, mitre.Finding{
					Technique: tech,
					Detail:    "Container appears to be running in PRIVILEGED mode",
					Evidence:  fmt.Sprintf("Effective capabilities: %s (all caps)", capHex),
					Remediation: "Run container without --privileged flag; use specific capabilities with --cap-add",
					RiskScore: 95,
				})
			}
		}
	}

	// Check for devices
	if _, err := os.Stat("/dev/sda"); err == nil {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique: tech,
			Detail:    "Host block devices accessible from container",
			Evidence:  "/dev/sda is accessible - host filesystem can be mounted",
			Remediation: "Remove --privileged flag and restrict device access",
			RiskScore: 95,
		})
	}
}

func (m *ContainerModule) checkMountedHostPaths(result *AssessmentResult, isContainer bool) {
	if !isContainer {
		return
	}
	tech := mitre.PrivEscTechniques["T1611"]

	content, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return
	}

	sensitiveMounts := []string{"/etc", "/root", "/home", "/var/run/docker.sock", "/proc/sys"}
	for _, line := range strings.Split(string(content), "\n") {
		for _, sm := range sensitiveMounts {
			if strings.Contains(line, sm) && !strings.HasPrefix(line, "proc") {
				result.Findings = append(result.Findings, mitre.Finding{
					Technique: mitre.Technique{
						ID: tech.ID, Name: tech.Name, Severity: "HIGH",
						Tactic: tech.Tactic,
					},
					Detail:    fmt.Sprintf("Sensitive host path mounted: %s", sm),
					Evidence:  truncate(line, 200),
					Remediation: "Remove unnecessary host volume mounts; use read-only mounts where possible",
					RiskScore: 75,
				})
				break
			}
		}
	}
}

func (m *ContainerModule) checkNamespaces(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1055.008"]

	// Check ptrace scope
	content, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err == nil {
		val := strings.TrimSpace(string(content))
		if val == "0" {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: tech,
				Detail:    "Ptrace scope set to 0 (classic ptrace permissions)",
				Evidence:  "Any process can ptrace any other process owned by the same user",
				Remediation: "Set kernel.yama.ptrace_scope = 1 or higher",
				RiskScore: 70,
			})
		}
	}

	// Check user namespace availability
	content, err = os.ReadFile("/proc/sys/user/max_user_namespaces")
	if err == nil {
		val := strings.TrimSpace(string(content))
		if val != "0" {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: mitre.Technique{
					ID: "T1611", Name: "Escape to Host",
					Severity: "MEDIUM", Tactic: "Privilege Escalation",
				},
				Detail:    "User namespaces enabled",
				Evidence:  fmt.Sprintf("max_user_namespaces = %s | May enable certain kernel exploits", val),
				Remediation: "Disable if not required: sysctl user.max_user_namespaces=0",
				RiskScore: 45,
			})
		}
	}
}

func (m *ContainerModule) checkCgroupEscape(result *AssessmentResult, isContainer bool) {
	if !isContainer {
		return
	}
	tech := mitre.PrivEscTechniques["T1611"]

	// Check if cgroup v1 release_agent is writable
	releaseAgent := "/sys/fs/cgroup/*/release_agent"
	out, _ := exec.Command("bash", "-c", fmt.Sprintf("ls %s 2>/dev/null", releaseAgent)).CombinedOutput()
	files := strings.TrimSpace(string(out))
	if files != "" {
		for _, f := range strings.Split(files, "\n") {
			info, err := os.Stat(f)
			if err != nil {
				continue
			}
			if info.Mode()&0002 != 0 {
				result.Findings = append(result.Findings, mitre.Finding{
					Technique: tech,
					Detail:    fmt.Sprintf("Writable cgroup release_agent: %s", f),
					Evidence:  "Can be used for container escape via cgroup notify_on_release",
					Remediation: "Run container with restricted cgroup access; use cgroup v2",
					RiskScore: 95,
				})
			}
		}
	}

	// Check for sys/kernel access
	sysFiles := []string{"/proc/sysrq-trigger", "/proc/sys/kernel/core_pattern"}
	for _, f := range sysFiles {
		if _, err := os.OpenFile(f, os.O_WRONLY, 0); err == nil {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: tech,
				Detail:    fmt.Sprintf("Writable sensitive proc file: %s", f),
				Evidence:  "Can potentially be used for container escape",
				Remediation: "Use read-only /proc mount or restrict access with AppArmor/SELinux",
				RiskScore: 85,
			})
		}
	}
}

func (m *ContainerModule) checkKubernetes(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1053.007"]

	// Check for K8s service account token
	tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	if _, err := os.Stat(tokenPath); err == nil {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique: mitre.Technique{
				ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
				SubName: tech.SubName, Severity: "HIGH", Tactic: tech.Tactic,
			},
			Detail:    "Kubernetes service account token found",
			Evidence:  fmt.Sprintf("Token at: %s | May grant cluster API access", tokenPath),
			Remediation: "Use automountServiceAccountToken: false if API access is not needed",
			RiskScore: 70,
		})
	}

	// Check for Kubernetes environment variables
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique: mitre.Technique{
				ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
				SubName: tech.SubName, Severity: "INFO", Tactic: tech.Tactic,
			},
			Detail:    "Running inside Kubernetes cluster",
			Evidence:  fmt.Sprintf("K8s API: %s:%s", os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")),
			RiskScore: 20,
		})
	}
}
