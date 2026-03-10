package assessor

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/privesc-toolkit/internal/mitre"
)

type KernelModule struct{}

func (m *KernelModule) Name() string        { return "Kernel & Exploit Vector Analysis" }
func (m *KernelModule) Description() string  { return "Checks kernel version, known CVEs, and exploit vectors (T1068)" }
func (m *KernelModule) TechniqueIDs() []string { return []string{"T1068"} }

// KnownKernelCVE represents a known kernel vulnerability
type KnownKernelCVE struct {
	CVE         string
	Name        string
	Description string
	MinVersion  string
	MaxVersion  string
	Severity    string
}

var knownKernelCVEs = []KnownKernelCVE{
	{"CVE-2022-0847", "DirtyPipe", "Overwrite data in arbitrary read-only files, leading to privilege escalation", "5.8", "5.16.10", "CRITICAL"},
	{"CVE-2021-4034", "PwnKit", "pkexec local privilege escalation via crafted environment", "all", "all", "CRITICAL"},
	{"CVE-2021-3493", "OverlayFS PrivEsc", "Unprivileged user namespace overlayfs escalation (Ubuntu)", "4.0", "5.11", "CRITICAL"},
	{"CVE-2022-2588", "RouteAdvt", "Use-after-free in route4 filter leading to privilege escalation", "4.0", "5.19", "HIGH"},
	{"CVE-2022-34918", "Netfilter nft_set", "Heap buffer overflow in nf_tables leading to privilege escalation", "5.8", "5.18.9", "CRITICAL"},
	{"CVE-2022-0185", "FSContext Heap Overflow", "Integer underflow in fs_context.c leading to heap overflow", "5.1", "5.16.1", "CRITICAL"},
	{"CVE-2023-0386", "OverlayFS Copy-Up", "UID/GID mapping bypass in overlayfs copy-up", "5.11", "6.2", "HIGH"},
	{"CVE-2023-32233", "Netfilter nf_tables", "Use-after-free in nf_tables batch processing", "5.0", "6.3.1", "CRITICAL"},
	{"CVE-2023-2640", "GameOver(lay)", "OverlayFS privilege escalation (Ubuntu specific)", "5.15", "6.2", "HIGH"},
	{"CVE-2023-3269", "StackRot", "Use-after-free in maple tree VMA management", "6.1", "6.4.1", "HIGH"},
	{"CVE-2023-4911", "Looney Tunables", "glibc ld.so buffer overflow via GLIBC_TUNABLES", "all", "all", "CRITICAL"},
	{"CVE-2024-1086", "nf_tables Use-After-Free", "Privilege escalation via nf_tables verdict handling", "5.14", "6.7.1", "CRITICAL"},
}

func (m *KernelModule) Run() AssessmentResult {
	start := time.Now()
	result := AssessmentResult{ModuleName: m.Name()}

	tech := mitre.PrivEscTechniques["T1068"]

	// Get kernel version
	kernelVersion := getKernelVersion()
	result.Findings = append(result.Findings, mitre.Finding{
		Technique: mitre.Technique{
			ID: tech.ID, Name: tech.Name, Severity: "INFO",
			Tactic: tech.Tactic,
		},
		Detail:    fmt.Sprintf("Kernel version: %s | Architecture: %s", kernelVersion, runtime.GOARCH),
		Evidence:  "Baseline information for kernel vulnerability assessment",
		RiskScore: 10,
	})

	// Check known CVEs against kernel version
	for _, cve := range knownKernelCVEs {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique: mitre.Technique{
				ID: tech.ID, Name: tech.Name, Severity: cve.Severity,
				Tactic:    tech.Tactic,
				Detection: "Verify kernel version and patch level against known CVE databases",
			},
			Detail:      fmt.Sprintf("[%s] %s - %s", cve.CVE, cve.Name, cve.Description),
			Evidence:    fmt.Sprintf("Affected versions: %s to %s | Current: %s | VERIFY MANUALLY", cve.MinVersion, cve.MaxVersion, kernelVersion),
			Remediation: fmt.Sprintf("Update kernel to latest patched version. Check: https://nvd.nist.gov/vuln/detail/%s", cve.CVE),
			RiskScore:   mitre.SeverityScore(cve.Severity),
		})
	}

	// Check kernel protections
	m.checkKernelProtections(&result)

	// Check loaded kernel modules
	m.checkKernelModules(&result)

	// Check compiler availability (for exploit compilation)
	m.checkCompilerAvailability(&result)

	result.Duration = time.Since(start).String()
	return result
}

func (m *KernelModule) checkKernelProtections(result *AssessmentResult) {
	protections := map[string]struct {
		file     string
		expected string
		desc     string
		severity string
	}{
		"ASLR": {"/proc/sys/kernel/randomize_va_space", "2", "Address Space Layout Randomization", "HIGH"},
		"ptrace_scope": {"/proc/sys/kernel/yama/ptrace_scope", "1", "Ptrace protection scope", "HIGH"},
		"kptr_restrict": {"/proc/sys/kernel/kptr_restrict", "1", "Kernel pointer restriction", "MEDIUM"},
		"dmesg_restrict": {"/proc/sys/kernel/dmesg_restrict", "1", "Restrict dmesg to privileged users", "MEDIUM"},
		"perf_paranoid": {"/proc/sys/kernel/perf_event_paranoid", "2", "Restrict perf events", "MEDIUM"},
		"unprivileged_bpf": {"/proc/sys/kernel/unprivileged_bpf_disabled", "1", "Disable unprivileged BPF", "HIGH"},
		"unprivileged_userns": {"/proc/sys/kernel/unprivileged_userns_clone", "0", "Disable unprivileged user namespaces", "HIGH"},
		"sysrq": {"/proc/sys/kernel/sysrq", "0", "Magic SysRq key restriction", "LOW"},
		"core_uses_pid": {"/proc/sys/kernel/core_uses_pid", "1", "Include PID in core dump name", "LOW"},
	}

	for name, p := range protections {
		content, err := os.ReadFile(p.file)
		if err != nil {
			continue
		}
		val := strings.TrimSpace(string(content))
		if val != p.expected {
			sev := p.severity
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: mitre.Technique{
					ID: "T1068", Name: "Exploitation for Privilege Escalation",
					Severity: sev, Tactic: "Privilege Escalation",
				},
				Detail:      fmt.Sprintf("Kernel protection weakened: %s (%s)", name, p.desc),
				Evidence:    fmt.Sprintf("Current: %s | Expected: %s | File: %s", val, p.expected, p.file),
				Remediation: fmt.Sprintf("echo %s > %s", p.expected, p.file),
				RiskScore:   mitre.SeverityScore(sev),
			})
		}
	}

	// Check for kernel lockdown mode
	lockdownFile := "/sys/kernel/security/lockdown"
	content, err := os.ReadFile(lockdownFile)
	if err == nil {
		val := strings.TrimSpace(string(content))
		if strings.Contains(val, "[none]") {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: mitre.Technique{
					ID: "T1068", Name: "Exploitation for Privilege Escalation",
					Severity: "MEDIUM", Tactic: "Privilege Escalation",
				},
				Detail:      "Kernel lockdown mode: disabled",
				Evidence:    fmt.Sprintf("Current: %s", val),
				Remediation: "Enable kernel lockdown (integrity or confidentiality mode) via boot parameters",
				RiskScore:   50,
			})
		}
	}
}

func (m *KernelModule) checkKernelModules(result *AssessmentResult) {
	out, err := exec.Command("lsmod").CombinedOutput()
	if err != nil {
		return
	}
	tech := mitre.PrivEscTechniques["T1547.006"]
	output := string(out)

	riskyModules := map[string]string{
		"overlay":     "OverlayFS loaded - check for overlay-related kernel CVEs",
		"nf_tables":   "nf_tables loaded - check for netfilter privilege escalation CVEs",
		"ip_tables":   "iptables loaded - check for filtering bypass possibilities",
		"vhost_net":   "vhost-net loaded - potential VM escape vector",
		"kvm":         "KVM loaded - check for VM escape vulnerabilities",
		"fuse":        "FUSE loaded - user-space filesystem could be abused",
	}

	for mod, desc := range riskyModules {
		if strings.Contains(output, mod) {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: mitre.Technique{
					ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
					SubName: tech.SubName, Severity: "MEDIUM", Tactic: tech.Tactic,
				},
				Detail:      fmt.Sprintf("Potentially risky kernel module loaded: %s", mod),
				Evidence:    desc,
				Remediation: fmt.Sprintf("Review if module '%s' is required; blacklist if not needed", mod),
				RiskScore:   40,
			})
		}
	}

	// Check if module loading is unrestricted
	modProbe, err := os.ReadFile("/proc/sys/kernel/modules_disabled")
	if err == nil && strings.TrimSpace(string(modProbe)) == "0" {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique: tech,
			Detail:    "Kernel module loading is not disabled",
			Evidence:  "/proc/sys/kernel/modules_disabled = 0",
			Remediation: "Set modules_disabled=1 after boot to prevent module loading",
			RiskScore: 60,
		})
	}
}

func (m *KernelModule) checkCompilerAvailability(result *AssessmentResult) {
	compilers := []string{"gcc", "cc", "g++", "make", "as", "ld"}
	found := []string{}
	for _, c := range compilers {
		if path, err := exec.LookPath(c); err == nil {
			found = append(found, path)
		}
	}
	if len(found) > 0 {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique: mitre.Technique{
				ID: "T1068", Name: "Exploitation for Privilege Escalation",
				Severity: "MEDIUM", Tactic: "Privilege Escalation",
			},
			Detail:      "Compilation tools available on system",
			Evidence:    fmt.Sprintf("Found: %s", strings.Join(found, ", ")),
			Remediation: "Remove compilers from production systems to impede exploit compilation",
			RiskScore:   40,
		})
	}
}

func getKernelVersion() string {
	out, err := exec.Command("uname", "-r").CombinedOutput()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}
