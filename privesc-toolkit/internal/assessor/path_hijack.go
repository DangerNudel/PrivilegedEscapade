package assessor

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/privesc-toolkit/internal/mitre"
)

type PathHijackModule struct{}

func (m *PathHijackModule) Name() string        { return "Execution Flow Hijacking Analysis" }
func (m *PathHijackModule) Description() string  { return "Checks for PATH hijacking, LD_PRELOAD, library path, and RPATH vulnerabilities (T1574)" }
func (m *PathHijackModule) TechniqueIDs() []string {
	return []string{"T1574", "T1574.006", "T1574.007"}
}

func (m *PathHijackModule) Run() AssessmentResult {
	start := time.Now()
	result := AssessmentResult{ModuleName: m.Name()}

	m.checkPATHDirs(&result)
	m.checkLDPreload(&result)
	m.checkLDLibraryPath(&result)
	m.checkLDSoConf(&result)
	m.checkLibraryDirPerms(&result)
	m.checkCapabilities(&result)
	m.checkRPATH(&result)

	result.Duration = time.Since(start).String()
	return result
}

func (m *PathHijackModule) checkPATHDirs(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1574.007"]

	pathEnv := os.Getenv("PATH")
	dirs := strings.Split(pathEnv, ":")

	for i, dir := range dirs {
		if dir == "" || dir == "." {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique:   tech,
				Detail:      fmt.Sprintf("Current directory '.' in PATH at position %d", i),
				Evidence:    fmt.Sprintf("PATH=%s", pathEnv),
				Remediation: "Remove '.' or empty entries from PATH",
				RiskScore:   80,
			})
			continue
		}

		info, err := os.Stat(dir)
		if err != nil {
			continue
		}

		if info.Mode()&0002 != 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique:   tech,
				Detail:      fmt.Sprintf("World-writable directory in PATH: %s (position %d)", dir, i),
				Evidence:    fmt.Sprintf("Permissions: %s | Any user can place malicious binaries here", info.Mode().String()),
				Remediation: fmt.Sprintf("chmod o-w %s or remove from PATH", dir),
				RiskScore:   85,
			})
		}

		if info.Mode()&0020 != 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: mitre.Technique{
					ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
					SubName: tech.SubName, Severity: "MEDIUM", Tactic: tech.Tactic,
				},
				Detail:      fmt.Sprintf("Group-writable directory in PATH: %s (position %d)", dir, i),
				Evidence:    fmt.Sprintf("Permissions: %s", info.Mode().String()),
				Remediation: fmt.Sprintf("chmod g-w %s", dir),
				RiskScore:   55,
			})
		}
	}
}

func (m *PathHijackModule) checkLDPreload(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1574.006"]

	// Check LD_PRELOAD environment variable
	ldPreload := os.Getenv("LD_PRELOAD")
	if ldPreload != "" {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique:   tech,
			Detail:      "LD_PRELOAD environment variable is set",
			Evidence:    fmt.Sprintf("LD_PRELOAD=%s", ldPreload),
			Remediation: "Investigate why LD_PRELOAD is set; remove if not required",
			RiskScore:   80,
		})
	}

	// Check /etc/ld.so.preload
	preloadFile := "/etc/ld.so.preload"
	content, err := os.ReadFile(preloadFile)
	if err == nil {
		entries := strings.TrimSpace(string(content))
		if entries != "" {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique:   tech,
				Detail:      "Libraries loaded via /etc/ld.so.preload",
				Evidence:    entries,
				Remediation: "Review entries in /etc/ld.so.preload for unauthorized libraries",
				RiskScore:   70,
			})
		}

		// Check file permissions
		info, err := os.Stat(preloadFile)
		if err == nil && info.Mode()&0022 != 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: tech,
				Detail:    fmt.Sprintf("Writable ld.so.preload: %s", preloadFile),
				Evidence:  fmt.Sprintf("Permissions: %s", info.Mode().String()),
				Remediation: "chmod 0644 /etc/ld.so.preload; chown root:root /etc/ld.so.preload",
				RiskScore: 90,
			})
		}
	}
}

func (m *PathHijackModule) checkLDLibraryPath(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1574.006"]

	ldPath := os.Getenv("LD_LIBRARY_PATH")
	if ldPath != "" {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique: mitre.Technique{
				ID: tech.ID, SubID: tech.SubID, Name: tech.Name,
				SubName: tech.SubName, Severity: "MEDIUM", Tactic: tech.Tactic,
			},
			Detail:      "LD_LIBRARY_PATH environment variable is set",
			Evidence:    fmt.Sprintf("LD_LIBRARY_PATH=%s", ldPath),
			Remediation: "Review LD_LIBRARY_PATH for untrusted directories",
			RiskScore:   50,
		})

		// Check each directory in LD_LIBRARY_PATH
		for _, dir := range strings.Split(ldPath, ":") {
			if isWritableByCurrentUser(dir) {
				result.Findings = append(result.Findings, mitre.Finding{
					Technique: tech,
					Detail:    fmt.Sprintf("Writable directory in LD_LIBRARY_PATH: %s", dir),
					Evidence:  "Malicious shared libraries can be placed here for hijacking",
					Remediation: fmt.Sprintf("Remove %s from LD_LIBRARY_PATH or fix permissions", dir),
					RiskScore: 80,
				})
			}
		}
	}
}

func (m *PathHijackModule) checkLDSoConf(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1574.006"]

	// Check /etc/ld.so.conf and /etc/ld.so.conf.d/
	ldConf := "/etc/ld.so.conf"
	info, err := os.Stat(ldConf)
	if err == nil && info.Mode()&0002 != 0 {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique: tech,
			Detail:    "World-writable /etc/ld.so.conf",
			Evidence:  fmt.Sprintf("Permissions: %s", info.Mode().String()),
			Remediation: "chmod 0644 /etc/ld.so.conf",
			RiskScore: 90,
		})
	}

	confDir := "/etc/ld.so.conf.d"
	if isWritableByCurrentUser(confDir) {
		result.Findings = append(result.Findings, mitre.Finding{
			Technique: tech,
			Detail:    "Writable /etc/ld.so.conf.d/ directory",
			Evidence:  "Attacker can add new library search paths",
			Remediation: "chmod 0755 /etc/ld.so.conf.d",
			RiskScore: 85,
		})
	}

	// Check for writable library directories referenced in ld.so.conf
	content, err := os.ReadFile(ldConf)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "include") {
			continue
		}
		if isWritableByCurrentUser(line) {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique: tech,
				Detail:    fmt.Sprintf("Writable library directory in ld.so.conf: %s", line),
				Evidence:  "Shared libraries in this path will be loaded by system programs",
				Remediation: fmt.Sprintf("Fix permissions on %s", line),
				RiskScore: 80,
			})
		}
	}
}

func (m *PathHijackModule) checkLibraryDirPerms(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1574.006"]

	libDirs := []string{
		"/lib", "/lib64", "/usr/lib", "/usr/lib64",
		"/usr/local/lib", "/usr/local/lib64",
	}

	for _, dir := range libDirs {
		info, err := os.Stat(dir)
		if err != nil {
			continue
		}
		if info.Mode()&0002 != 0 {
			result.Findings = append(result.Findings, mitre.Finding{
				Technique:   tech,
				Detail:      fmt.Sprintf("World-writable system library directory: %s", dir),
				Evidence:    fmt.Sprintf("Permissions: %s", info.Mode().String()),
				Remediation: fmt.Sprintf("chmod 0755 %s", dir),
				RiskScore:   95,
			})
		}
	}
}

func (m *PathHijackModule) checkCapabilities(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1548"]

	out, err := exec.Command("bash", "-c", "find / -type f -exec getcap {} + 2>/dev/null | head -100").CombinedOutput()
	if err != nil {
		return
	}

	dangerousCaps := map[string]string{
		"cap_setuid":       "Can set process UID - allows privilege escalation to root",
		"cap_setgid":       "Can set process GID - allows group escalation",
		"cap_sys_admin":    "Nearly equivalent to root - can mount filesystems, use BPF, etc.",
		"cap_sys_ptrace":   "Can trace any process - allows code injection",
		"cap_dac_override": "Bypasses file read/write/execute permission checks",
		"cap_dac_read_search": "Bypasses file read and directory search permission checks",
		"cap_net_raw":      "Can craft raw packets - allows network attacks",
		"cap_net_admin":    "Can modify network configuration and routing",
		"cap_sys_module":   "Can load kernel modules",
		"cap_fowner":       "Bypasses file ownership checks",
		"cap_chown":        "Can change file ownership",
		"cap_net_bind_service": "Can bind to privileged ports",
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		for cap, desc := range dangerousCaps {
			if strings.Contains(line, cap) {
				sev := "HIGH"
				score := 75
				if cap == "cap_setuid" || cap == "cap_sys_admin" || cap == "cap_sys_ptrace" || cap == "cap_sys_module" {
					sev = "CRITICAL"
					score = 90
				}
				result.Findings = append(result.Findings, mitre.Finding{
					Technique: mitre.Technique{
						ID: tech.ID, Name: tech.Name, Severity: sev,
						Tactic: tech.Tactic,
					},
					Detail:      fmt.Sprintf("Dangerous capability found: %s", line),
					Evidence:    desc,
					Remediation: fmt.Sprintf("Remove capability: setcap -r %s", strings.Fields(line)[0]),
					RiskScore:   score,
				})
				break
			}
		}
	}
}

func (m *PathHijackModule) checkRPATH(result *AssessmentResult) {
	tech := mitre.PrivEscTechniques["T1574.006"]

	// Check SUID binaries for RPATH/RUNPATH with writable dirs
	suidBins := findSUIDBinaries()
	for _, bin := range suidBins {
		out, err := exec.Command("readelf", "-d", bin).CombinedOutput()
		if err != nil {
			continue
		}
		output := string(out)
		if strings.Contains(output, "RPATH") || strings.Contains(output, "RUNPATH") {
			for _, line := range strings.Split(output, "\n") {
				if strings.Contains(line, "RPATH") || strings.Contains(line, "RUNPATH") {
					// Extract path
					parts := strings.Split(line, "[")
					if len(parts) > 1 {
						rpath := strings.TrimRight(parts[1], "]")
						for _, p := range strings.Split(rpath, ":") {
							if isWritableByCurrentUser(p) {
								result.Findings = append(result.Findings, mitre.Finding{
									Technique: tech,
									Detail:    fmt.Sprintf("SUID binary with writable RPATH: %s -> %s", bin, p),
									Evidence:  "Malicious library can be placed in RPATH to hijack SUID binary execution",
									Remediation: fmt.Sprintf("Recompile %s without RPATH or fix directory permissions", bin),
									RiskScore: 90,
								})
							}
						}
					}
				}
			}
		}
	}
}
