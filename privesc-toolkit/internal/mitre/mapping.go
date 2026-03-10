package mitre

// Technique represents a MITRE ATT&CK technique
type Technique struct {
	ID          string
	Name        string
	SubID       string
	SubName     string
	Tactic      string
	Description string
	Detection   string
	Platforms   []string
	Severity    string // CRITICAL, HIGH, MEDIUM, LOW, INFO
}

// Finding represents an assessment finding mapped to a technique
type Finding struct {
	Technique   Technique
	Detail      string
	Evidence    string
	Remediation string
	RiskScore   int // 0-100
}

// PrivEscTechniques contains all MITRE ATT&CK TA0004 Privilege Escalation techniques
var PrivEscTechniques = map[string]Technique{
	// T1548 - Abuse Elevation Control Mechanism
	"T1548": {
		ID: "T1548", Name: "Abuse Elevation Control Mechanism",
		Tactic: "Privilege Escalation", Severity: "CRITICAL",
		Description: "Adversaries may circumvent mechanisms designed to control elevated privileges to gain higher-level permissions.",
		Detection:   "Monitor for changes to security-related OS configuration, execution of setuid/setgid programs, and modifications to sudo configuration.",
		Platforms:   []string{"Linux", "macOS", "Windows"},
	},
	"T1548.001": {
		ID: "T1548", SubID: "T1548.001", Name: "Abuse Elevation Control Mechanism", SubName: "Setuid and Setgid",
		Tactic: "Privilege Escalation", Severity: "CRITICAL",
		Description: "Adversaries may abuse SUID/SGID bits to execute binaries with elevated privileges.",
		Detection:   "Monitor file systems for SUID/SGID bit changes. Audit new SUID/SGID binaries.",
		Platforms:   []string{"Linux", "macOS"},
	},
	"T1548.002": {
		ID: "T1548", SubID: "T1548.002", Name: "Abuse Elevation Control Mechanism", SubName: "Bypass User Account Control",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may bypass UAC mechanisms to elevate process privileges on Windows systems.",
		Detection:   "Monitor registry changes, COM object modifications, and process creation with elevated tokens.",
		Platforms:   []string{"Windows"},
	},
	"T1548.003": {
		ID: "T1548", SubID: "T1548.003", Name: "Abuse Elevation Control Mechanism", SubName: "Sudo and Sudo Caching",
		Tactic: "Privilege Escalation", Severity: "CRITICAL",
		Description: "Adversaries may abuse sudo or its caching to execute commands with elevated privileges.",
		Detection:   "Monitor sudo configuration files and timestamp modifications.",
		Platforms:   []string{"Linux", "macOS"},
	},
	"T1548.004": {
		ID: "T1548", SubID: "T1548.004", Name: "Abuse Elevation Control Mechanism", SubName: "Elevated Execution with Prompt",
		Tactic: "Privilege Escalation", Severity: "MEDIUM",
		Description: "Adversaries may leverage AuthorizationExecuteWithPrivileges or similar APIs to escalate privileges via user prompts.",
		Detection:   "Monitor API calls to AuthorizationExecuteWithPrivileges and similar functions.",
		Platforms:   []string{"macOS"},
	},

	// T1134 - Access Token Manipulation
	"T1134": {
		ID: "T1134", Name: "Access Token Manipulation",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may modify access tokens to operate under a different security context to perform actions and bypass access controls.",
		Detection:   "Monitor for unusual token creation, duplication, and impersonation events.",
		Platforms:   []string{"Windows"},
	},
	"T1134.001": {
		ID: "T1134", SubID: "T1134.001", Name: "Access Token Manipulation", SubName: "Token Impersonation/Theft",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may duplicate then impersonate another user's existing token to escalate privileges.",
		Detection:   "Monitor for API calls to DuplicateToken, ImpersonateLoggedOnUser, SetThreadToken.",
		Platforms:   []string{"Windows"},
	},
	"T1134.002": {
		ID: "T1134", SubID: "T1134.002", Name: "Access Token Manipulation", SubName: "Create Process with Token",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may create a new process with an existing token to escalate privileges.",
		Detection:   "Monitor for calls to CreateProcessWithToken or CreateProcessAsUser.",
		Platforms:   []string{"Windows"},
	},
	"T1134.003": {
		ID: "T1134", SubID: "T1134.003", Name: "Access Token Manipulation", SubName: "Make and Impersonate Token",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may make new tokens and impersonate users to escalate privileges with LogonUser/ImpersonateLoggedOnUser.",
		Detection:   "Monitor for LogonUser API calls, especially with LOGON32_LOGON_NEW_CREDENTIALS.",
		Platforms:   []string{"Windows"},
	},
	"T1134.004": {
		ID: "T1134", SubID: "T1134.004", Name: "Access Token Manipulation", SubName: "Parent PID Spoofing",
		Tactic: "Privilege Escalation", Severity: "MEDIUM",
		Description: "Adversaries may spoof the parent process identifier to evade detection and escalate privileges.",
		Detection:   "Monitor for mismatches between a process's PPID and its expected parent.",
		Platforms:   []string{"Windows"},
	},

	// T1547 - Boot or Logon Autostart Execution
	"T1547": {
		ID: "T1547", Name: "Boot or Logon Autostart Execution",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may configure system settings to automatically execute a program during system boot or logon.",
		Detection:   "Monitor registry Run keys, startup folders, init scripts, and systemd units.",
		Platforms:   []string{"Linux", "macOS", "Windows"},
	},
	"T1547.001": {
		ID: "T1547", SubID: "T1547.001", Name: "Boot or Logon Autostart Execution", SubName: "Registry Run Keys / Startup Folder",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may achieve persistence/privilege escalation via registry Run keys or startup folder entries.",
		Detection:   "Monitor Run/RunOnce registry keys and Startup folder for new entries.",
		Platforms:   []string{"Windows"},
	},
	"T1547.003": {
		ID: "T1547", SubID: "T1547.003", Name: "Boot or Logon Autostart Execution", SubName: "Time Providers",
		Tactic: "Privilege Escalation", Severity: "MEDIUM",
		Description: "Adversaries may abuse time provider DLLs to execute code at system startup.",
		Detection:   "Monitor W32Time service DLL registrations.",
		Platforms:   []string{"Windows"},
	},
	"T1547.004": {
		ID: "T1547", SubID: "T1547.004", Name: "Boot or Logon Autostart Execution", SubName: "Winlogon Helper DLL",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may abuse Winlogon helper DLLs for persistence and privilege escalation.",
		Detection:   "Monitor Winlogon registry entries for Shell/Userinit/Notify changes.",
		Platforms:   []string{"Windows"},
	},
	"T1547.006": {
		ID: "T1547", SubID: "T1547.006", Name: "Boot or Logon Autostart Execution", SubName: "Kernel Modules and Extensions",
		Tactic: "Privilege Escalation", Severity: "CRITICAL",
		Description: "Adversaries may modify the kernel to automatically execute programs at boot via loadable kernel modules.",
		Detection:   "Monitor for new kernel modules and extensions being loaded.",
		Platforms:   []string{"Linux", "macOS"},
	},
	"T1547.009": {
		ID: "T1547", SubID: "T1547.009", Name: "Boot or Logon Autostart Execution", SubName: "Shortcut Modification",
		Tactic: "Privilege Escalation", Severity: "MEDIUM",
		Description: "Adversaries may create or modify shortcuts to run malicious code during user logon.",
		Detection:   "Monitor .lnk file creation and modification in startup locations.",
		Platforms:   []string{"Windows"},
	},
	"T1547.012": {
		ID: "T1547", SubID: "T1547.012", Name: "Boot or Logon Autostart Execution", SubName: "Print Processors",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may abuse print processors to load malicious DLLs during boot.",
		Detection:   "Monitor print processor DLL registrations in the registry.",
		Platforms:   []string{"Windows"},
	},
	"T1547.013": {
		ID: "T1547", SubID: "T1547.013", Name: "Boot or Logon Autostart Execution", SubName: "XDG Autostart Entries",
		Tactic: "Privilege Escalation", Severity: "MEDIUM",
		Description: "Adversaries may add XDG Autostart entries to execute programs at user logon on Linux systems.",
		Detection:   "Monitor XDG autostart directories for new .desktop files.",
		Platforms:   []string{"Linux"},
	},
	"T1547.014": {
		ID: "T1547", SubID: "T1547.014", Name: "Boot or Logon Autostart Execution", SubName: "Active Setup",
		Tactic: "Privilege Escalation", Severity: "MEDIUM",
		Description: "Adversaries may achieve persistence by adding entries to Active Setup in the Windows registry.",
		Detection:   "Monitor Active Setup registry keys for new StubPath values.",
		Platforms:   []string{"Windows"},
	},
	"T1547.015": {
		ID: "T1547", SubID: "T1547.015", Name: "Boot or Logon Autostart Execution", SubName: "Login Items",
		Tactic: "Privilege Escalation", Severity: "MEDIUM",
		Description: "Adversaries may add login items to execute malicious programs upon user logon on macOS.",
		Detection:   "Monitor login item plist files and shared file list modifications.",
		Platforms:   []string{"macOS"},
	},

	// T1037 - Boot or Logon Initialization Scripts
	"T1037": {
		ID: "T1037", Name: "Boot or Logon Initialization Scripts",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may use scripts automatically executed at boot or logon to establish persistence and escalate privileges.",
		Detection:   "Monitor for changes to logon scripts, profile scripts, and rc.local.",
		Platforms:   []string{"Linux", "macOS", "Windows"},
	},
	"T1037.001": {
		ID: "T1037", SubID: "T1037.001", Name: "Boot or Logon Initialization Scripts", SubName: "Logon Script (Windows)",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may use Windows logon scripts to gain persistence and escalate privileges.",
		Detection:   "Monitor UserInitMprLogonScript registry key and Group Policy logon scripts.",
		Platforms:   []string{"Windows"},
	},
	"T1037.002": {
		ID: "T1037", SubID: "T1037.002", Name: "Boot or Logon Initialization Scripts", SubName: "Login Hook",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may use login hooks to execute code as root during the login process on macOS.",
		Detection:   "Monitor com.apple.loginwindow plist for LoginHook and LogoutHook entries.",
		Platforms:   []string{"macOS"},
	},
	"T1037.003": {
		ID: "T1037", SubID: "T1037.003", Name: "Boot or Logon Initialization Scripts", SubName: "Network Logon Script",
		Tactic: "Privilege Escalation", Severity: "MEDIUM",
		Description: "Adversaries may use network logon scripts that run on domain join or VPN connection.",
		Detection:   "Monitor Group Policy logon script execution on network events.",
		Platforms:   []string{"Windows"},
	},
	"T1037.004": {
		ID: "T1037", SubID: "T1037.004", Name: "Boot or Logon Initialization Scripts", SubName: "RC Scripts",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may establish persistence by modifying RC scripts executed during Unix-based boot process.",
		Detection:   "Monitor /etc/rc.local, /etc/rc.d/, and init.d scripts for modifications.",
		Platforms:   []string{"Linux", "macOS"},
	},
	"T1037.005": {
		ID: "T1037", SubID: "T1037.005", Name: "Boot or Logon Initialization Scripts", SubName: "Startup Items",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may use startup items to execute malicious programs during boot on macOS.",
		Detection:   "Monitor /Library/StartupItems/ for new or modified scripts.",
		Platforms:   []string{"macOS"},
	},

	// T1543 - Create or Modify System Process
	"T1543": {
		ID: "T1543", Name: "Create or Modify System Process",
		Tactic: "Privilege Escalation", Severity: "CRITICAL",
		Description: "Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence.",
		Detection:   "Monitor for new systemd services, launch daemons, and Windows services.",
		Platforms:   []string{"Linux", "macOS", "Windows"},
	},
	"T1543.001": {
		ID: "T1543", SubID: "T1543.001", Name: "Create or Modify System Process", SubName: "Launch Agent",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may create or modify launch agents to execute code as the logged-in user.",
		Detection:   "Monitor LaunchAgent directories for new or modified plist files.",
		Platforms:   []string{"macOS"},
	},
	"T1543.002": {
		ID: "T1543", SubID: "T1543.002", Name: "Create or Modify System Process", SubName: "Systemd Service",
		Tactic: "Privilege Escalation", Severity: "CRITICAL",
		Description: "Adversaries may create or modify systemd services to execute malicious commands at startup.",
		Detection:   "Monitor systemd unit file directories for new or modified service files.",
		Platforms:   []string{"Linux"},
	},
	"T1543.003": {
		ID: "T1543", SubID: "T1543.003", Name: "Create or Modify System Process", SubName: "Windows Service",
		Tactic: "Privilege Escalation", Severity: "CRITICAL",
		Description: "Adversaries may create or modify Windows services to escalate privileges.",
		Detection:   "Monitor Windows service creation and modification via sc.exe, PowerShell, or registry.",
		Platforms:   []string{"Windows"},
	},
	"T1543.004": {
		ID: "T1543", SubID: "T1543.004", Name: "Create or Modify System Process", SubName: "Launch Daemon",
		Tactic: "Privilege Escalation", Severity: "CRITICAL",
		Description: "Adversaries may create or modify launch daemons to execute code as root.",
		Detection:   "Monitor LaunchDaemon directories for new or modified plist files.",
		Platforms:   []string{"macOS"},
	},

	// T1484 - Domain or Tenant Policy Modification
	"T1484": {
		ID: "T1484", Name: "Domain or Tenant Policy Modification",
		Tactic: "Privilege Escalation", Severity: "CRITICAL",
		Description: "Adversaries may modify domain or tenant-level policies to escalate privileges within a domain environment.",
		Detection:   "Monitor for Group Policy object modifications and domain trust changes.",
		Platforms:   []string{"Windows", "Azure AD", "SaaS"},
	},
	"T1484.001": {
		ID: "T1484", SubID: "T1484.001", Name: "Domain or Tenant Policy Modification", SubName: "Group Policy Modification",
		Tactic: "Privilege Escalation", Severity: "CRITICAL",
		Description: "Adversaries may modify Group Policy Objects to escalate privileges across a domain.",
		Detection:   "Monitor GPO changes in SYSVOL and Active Directory event logs (Event ID 5136).",
		Platforms:   []string{"Windows"},
	},
	"T1484.002": {
		ID: "T1484", SubID: "T1484.002", Name: "Domain or Tenant Policy Modification", SubName: "Trust Modification",
		Tactic: "Privilege Escalation", Severity: "CRITICAL",
		Description: "Adversaries may add new domain trusts or modify the properties of existing trusts.",
		Detection:   "Monitor for changes to domain trust objects and federation settings.",
		Platforms:   []string{"Windows", "Azure AD"},
	},

	// T1546 - Event Triggered Execution
	"T1546": {
		ID: "T1546", Name: "Event Triggered Execution",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events.",
		Detection:   "Monitor for changes to event-based execution mechanisms.",
		Platforms:   []string{"Linux", "macOS", "Windows"},
	},
	"T1546.001": {
		ID: "T1546", SubID: "T1546.001", Name: "Event Triggered Execution", SubName: "Change Default File Association",
		Tactic: "Privilege Escalation", Severity: "MEDIUM",
		Description: "Adversaries may change file associations to hijack execution when the associated file type is opened.",
		Detection:   "Monitor for changes to default file associations in registry or filesystem.",
		Platforms:   []string{"Windows"},
	},
	"T1546.002": {
		ID: "T1546", SubID: "T1546.002", Name: "Event Triggered Execution", SubName: "Screensaver",
		Tactic: "Privilege Escalation", Severity: "MEDIUM",
		Description: "Adversaries may establish persistence by modifying screensaver settings.",
		Detection:   "Monitor SCRNSAVE.EXE registry value modifications.",
		Platforms:   []string{"Windows"},
	},
	"T1546.003": {
		ID: "T1546", SubID: "T1546.003", Name: "Event Triggered Execution", SubName: "WMI Event Subscription",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may use WMI event subscriptions to execute code when specific events occur.",
		Detection:   "Monitor WMI event filter, consumer, and binding creation.",
		Platforms:   []string{"Windows"},
	},
	"T1546.004": {
		ID: "T1546", SubID: "T1546.004", Name: "Event Triggered Execution", SubName: "Unix Shell Configuration Modification",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may establish persistence through modification of shell configuration files (.bashrc, .profile, etc.).",
		Detection:   "Monitor shell config files for unauthorized modifications.",
		Platforms:   []string{"Linux", "macOS"},
	},
	"T1546.005": {
		ID: "T1546", SubID: "T1546.005", Name: "Event Triggered Execution", SubName: "Trap",
		Tactic: "Privilege Escalation", Severity: "MEDIUM",
		Description: "Adversaries may use the trap command to register code to execute when certain signals are received.",
		Detection:   "Monitor for the use of trap commands in shell scripts and profiles.",
		Platforms:   []string{"Linux", "macOS"},
	},
	"T1546.006": {
		ID: "T1546", SubID: "T1546.006", Name: "Event Triggered Execution", SubName: "LC_LOAD_DYLIB Addition",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may add LC_LOAD_DYLIB load commands to Mach-O binaries to load malicious libraries.",
		Detection:   "Monitor for changes to LC_LOAD_DYLIB headers in Mach-O binaries.",
		Platforms:   []string{"macOS"},
	},
	"T1546.008": {
		ID: "T1546", SubID: "T1546.008", Name: "Event Triggered Execution", SubName: "Accessibility Features",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may abuse accessibility features (sethc, utilman, osk, narrator) for privilege escalation.",
		Detection:   "Monitor for replacement or modification of accessibility binaries.",
		Platforms:   []string{"Windows"},
	},
	"T1546.009": {
		ID: "T1546", SubID: "T1546.009", Name: "Event Triggered Execution", SubName: "AppCert DLLs",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may use AppCert DLLs to establish persistence and elevate privileges.",
		Detection:   "Monitor AppCertDLLs registry key for new entries.",
		Platforms:   []string{"Windows"},
	},
	"T1546.010": {
		ID: "T1546", SubID: "T1546.010", Name: "Event Triggered Execution", SubName: "AppInit DLLs",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may use AppInit DLLs to escalate privileges by loading malicious DLLs into every process that loads user32.dll.",
		Detection:   "Monitor AppInit_DLLs and LoadAppInit_DLLs registry values.",
		Platforms:   []string{"Windows"},
	},
	"T1546.011": {
		ID: "T1546", SubID: "T1546.011", Name: "Event Triggered Execution", SubName: "Application Shimming",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may use application shimming to establish persistence or escalate privileges.",
		Detection:   "Monitor for new shim database (.sdb) installations.",
		Platforms:   []string{"Windows"},
	},
	"T1546.012": {
		ID: "T1546", SubID: "T1546.012", Name: "Event Triggered Execution", SubName: "Image File Execution Options Injection",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may use IFEO to intercept execution of binaries and redirect to malicious executables.",
		Detection:   "Monitor IFEO registry keys for Debugger value additions.",
		Platforms:   []string{"Windows"},
	},
	"T1546.013": {
		ID: "T1546", SubID: "T1546.013", Name: "Event Triggered Execution", SubName: "PowerShell Profile",
		Tactic: "Privilege Escalation", Severity: "MEDIUM",
		Description: "Adversaries may modify PowerShell profiles to execute malicious code on PowerShell startup.",
		Detection:   "Monitor PowerShell profile locations for modifications.",
		Platforms:   []string{"Windows"},
	},
	"T1546.014": {
		ID: "T1546", SubID: "T1546.014", Name: "Event Triggered Execution", SubName: "Emond",
		Tactic: "Privilege Escalation", Severity: "MEDIUM",
		Description: "Adversaries may use Event Monitor Daemon (emond) rules to execute code on macOS event triggers.",
		Detection:   "Monitor /etc/emond.d/ for new rule files.",
		Platforms:   []string{"macOS"},
	},
	"T1546.015": {
		ID: "T1546", SubID: "T1546.015", Name: "Event Triggered Execution", SubName: "Component Object Model Hijacking",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may hijack COM objects to establish persistence and escalate privileges.",
		Detection:   "Monitor for changes to CLSID registry entries and InprocServer32 values.",
		Platforms:   []string{"Windows"},
	},
	"T1546.016": {
		ID: "T1546", SubID: "T1546.016", Name: "Event Triggered Execution", SubName: "Installer Packages",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may abuse installer packages to execute malicious content during installation.",
		Detection:   "Monitor installer package execution and associated script/binary launches.",
		Platforms:   []string{"Linux", "macOS", "Windows"},
	},

	// T1068 - Exploitation for Privilege Escalation
	"T1068": {
		ID: "T1068", Name: "Exploitation for Privilege Escalation",
		Tactic: "Privilege Escalation", Severity: "CRITICAL",
		Description: "Adversaries may exploit software vulnerabilities to escalate privileges. This includes kernel exploits and application-level vulnerabilities.",
		Detection:   "Monitor for kernel versions with known vulnerabilities, unusual system calls, and application crash patterns.",
		Platforms:   []string{"Linux", "macOS", "Windows"},
	},

	// T1574 - Hijack Execution Flow
	"T1574": {
		ID: "T1574", Name: "Hijack Execution Flow",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may hijack the way operating systems run programs to execute their own malicious payloads.",
		Detection:   "Monitor for DLL search order anomalies, PATH hijacking, and LD_PRELOAD usage.",
		Platforms:   []string{"Linux", "macOS", "Windows"},
	},
	"T1574.001": {
		ID: "T1574", SubID: "T1574.001", Name: "Hijack Execution Flow", SubName: "DLL Search Order Hijacking",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may plant malicious DLLs in locations that take precedence in the DLL search order.",
		Detection:   "Monitor for DLLs loaded from unexpected locations.",
		Platforms:   []string{"Windows"},
	},
	"T1574.002": {
		ID: "T1574", SubID: "T1574.002", Name: "Hijack Execution Flow", SubName: "DLL Side-Loading",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may abuse DLL side-loading by planting malicious DLLs alongside legitimate applications.",
		Detection:   "Monitor for DLLs loaded from non-standard paths alongside executables.",
		Platforms:   []string{"Windows"},
	},
	"T1574.004": {
		ID: "T1574", SubID: "T1574.004", Name: "Hijack Execution Flow", SubName: "Dylib Hijacking",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may place malicious dylibs in locations searched before legitimate ones on macOS.",
		Detection:   "Monitor for dylib loads from unexpected paths and weak rpath entries.",
		Platforms:   []string{"macOS"},
	},
	"T1574.005": {
		ID: "T1574", SubID: "T1574.005", Name: "Hijack Execution Flow", SubName: "Executable Installer File Permissions Weakness",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may hijack installers by replacing executables in directories with weak file permissions.",
		Detection:   "Monitor for writes to installer directories and permission changes.",
		Platforms:   []string{"Windows"},
	},
	"T1574.006": {
		ID: "T1574", SubID: "T1574.006", Name: "Hijack Execution Flow", SubName: "Dynamic Linker Hijacking",
		Tactic: "Privilege Escalation", Severity: "CRITICAL",
		Description: "Adversaries may hijack the dynamic linker to load malicious libraries via LD_PRELOAD or LD_LIBRARY_PATH.",
		Detection:   "Monitor LD_PRELOAD, LD_LIBRARY_PATH env vars, and /etc/ld.so.preload.",
		Platforms:   []string{"Linux", "macOS"},
	},
	"T1574.007": {
		ID: "T1574", SubID: "T1574.007", Name: "Hijack Execution Flow", SubName: "Path Interception by PATH Environment Variable",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may place executables in PATH directories that are searched before the legitimate binary's directory.",
		Detection:   "Monitor for writable directories in PATH and new executables in early PATH entries.",
		Platforms:   []string{"Linux", "macOS", "Windows"},
	},
	"T1574.008": {
		ID: "T1574", SubID: "T1574.008", Name: "Hijack Execution Flow", SubName: "Path Interception by Search Order Hijacking",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may abuse the default search order to hijack execution flow.",
		Detection:   "Monitor process execution paths that differ from expected binary locations.",
		Platforms:   []string{"Windows"},
	},
	"T1574.009": {
		ID: "T1574", SubID: "T1574.009", Name: "Hijack Execution Flow", SubName: "Path Interception by Unquoted Path",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may exploit unquoted service paths to execute malicious binaries.",
		Detection:   "Monitor Windows services for unquoted paths containing spaces.",
		Platforms:   []string{"Windows"},
	},
	"T1574.010": {
		ID: "T1574", SubID: "T1574.010", Name: "Hijack Execution Flow", SubName: "Services File Permissions Weakness",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may replace service binaries in directories with weak file permissions.",
		Detection:   "Monitor service binary paths for write permissions by non-admin users.",
		Platforms:   []string{"Windows"},
	},
	"T1574.011": {
		ID: "T1574", SubID: "T1574.011", Name: "Hijack Execution Flow", SubName: "Services Registry Permissions Weakness",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may modify service registry keys with weak permissions to point to malicious executables.",
		Detection:   "Monitor service registry keys for permission changes and binary path modifications.",
		Platforms:   []string{"Windows"},
	},
	"T1574.012": {
		ID: "T1574", SubID: "T1574.012", Name: "Hijack Execution Flow", SubName: "COR_PROFILER",
		Tactic: "Privilege Escalation", Severity: "MEDIUM",
		Description: "Adversaries may use COR_PROFILER environment variable to hijack .NET CLR execution flow.",
		Detection:   "Monitor COR_ENABLE_PROFILING and COR_PROFILER environment variables.",
		Platforms:   []string{"Windows"},
	},
	"T1574.013": {
		ID: "T1574", SubID: "T1574.013", Name: "Hijack Execution Flow", SubName: "KernelCallbackTable",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may abuse the KernelCallbackTable to hijack process execution flow.",
		Detection:   "Monitor for modifications to PEB KernelCallbackTable entries.",
		Platforms:   []string{"Windows"},
	},

	// T1055 - Process Injection
	"T1055": {
		ID: "T1055", Name: "Process Injection",
		Tactic: "Privilege Escalation", Severity: "CRITICAL",
		Description: "Adversaries may inject code into processes to evade defenses and potentially elevate privileges.",
		Detection:   "Monitor for ptrace, process hollowing, and cross-process memory write operations.",
		Platforms:   []string{"Linux", "macOS", "Windows"},
	},
	"T1055.001": {
		ID: "T1055", SubID: "T1055.001", Name: "Process Injection", SubName: "Dynamic-link Library Injection",
		Tactic: "Privilege Escalation", Severity: "CRITICAL",
		Description: "Adversaries may inject DLLs into processes to escalate privileges.",
		Detection:   "Monitor for unusual DLL loading patterns and CreateRemoteThread API usage.",
		Platforms:   []string{"Windows"},
	},
	"T1055.002": {
		ID: "T1055", SubID: "T1055.002", Name: "Process Injection", SubName: "Portable Executable Injection",
		Tactic: "Privilege Escalation", Severity: "CRITICAL",
		Description: "Adversaries may inject portable executables into processes to evade defenses.",
		Detection:   "Monitor for VirtualAllocEx and WriteProcessMemory followed by CreateRemoteThread.",
		Platforms:   []string{"Windows"},
	},
	"T1055.003": {
		ID: "T1055", SubID: "T1055.003", Name: "Process Injection", SubName: "Thread Execution Hijacking",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may inject code into processes by suspending a thread and modifying its context.",
		Detection:   "Monitor for SuspendThread, SetThreadContext, and ResumeThread sequences.",
		Platforms:   []string{"Windows"},
	},
	"T1055.004": {
		ID: "T1055", SubID: "T1055.004", Name: "Process Injection", SubName: "Asynchronous Procedure Call",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may inject code into processes via asynchronous procedure calls.",
		Detection:   "Monitor for QueueUserAPC API calls targeting remote processes.",
		Platforms:   []string{"Windows"},
	},
	"T1055.005": {
		ID: "T1055", SubID: "T1055.005", Name: "Process Injection", SubName: "Thread Local Storage",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may inject code by manipulating Thread Local Storage callbacks.",
		Detection:   "Monitor for TLS callback manipulation in process memory.",
		Platforms:   []string{"Windows"},
	},
	"T1055.008": {
		ID: "T1055", SubID: "T1055.008", Name: "Process Injection", SubName: "Ptrace System Calls",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may use ptrace to inject code into running processes on Linux.",
		Detection:   "Monitor ptrace system calls and /proc/sys/kernel/yama/ptrace_scope.",
		Platforms:   []string{"Linux"},
	},
	"T1055.009": {
		ID: "T1055", SubID: "T1055.009", Name: "Process Injection", SubName: "Proc Memory",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may inject code by writing to /proc/[pid]/mem on Linux.",
		Detection:   "Monitor for writes to /proc/[pid]/mem and access to process memory files.",
		Platforms:   []string{"Linux"},
	},
	"T1055.011": {
		ID: "T1055", SubID: "T1055.011", Name: "Process Injection", SubName: "Extra Window Memory Injection",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may inject code through Extra Window Memory in graphical Windows processes.",
		Detection:   "Monitor for SetWindowLong/SetWindowLongPtr calls with modified callback pointers.",
		Platforms:   []string{"Windows"},
	},
	"T1055.012": {
		ID: "T1055", SubID: "T1055.012", Name: "Process Injection", SubName: "Process Hollowing",
		Tactic: "Privilege Escalation", Severity: "CRITICAL",
		Description: "Adversaries may create a process in a suspended state, unmap its memory, and write malicious code in its place.",
		Detection:   "Monitor for processes created in suspended state followed by memory unmapping.",
		Platforms:   []string{"Windows"},
	},
	"T1055.014": {
		ID: "T1055", SubID: "T1055.014", Name: "Process Injection", SubName: "VDSO Hijacking",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may hijack the VDSO to redirect system calls to malicious code.",
		Detection:   "Monitor for modifications to the vDSO mapping in process memory.",
		Platforms:   []string{"Linux"},
	},
	"T1055.015": {
		ID: "T1055", SubID: "T1055.015", Name: "Process Injection", SubName: "ListPlanting",
		Tactic: "Privilege Escalation", Severity: "MEDIUM",
		Description: "Adversaries may abuse list-view controls to inject code via LVM_SORTITEMS messages.",
		Detection:   "Monitor for cross-process LVM_SORTITEMS messages.",
		Platforms:   []string{"Windows"},
	},

	// T1053 - Scheduled Task/Job
	"T1053": {
		ID: "T1053", Name: "Scheduled Task/Job",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may abuse task scheduling to execute malicious code at elevated privileges.",
		Detection:   "Monitor scheduled task/job creation and modification.",
		Platforms:   []string{"Linux", "macOS", "Windows"},
	},
	"T1053.002": {
		ID: "T1053", SubID: "T1053.002", Name: "Scheduled Task/Job", SubName: "At",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may abuse the at utility to schedule jobs for code execution on Linux/macOS/Windows.",
		Detection:   "Monitor at job creation via at command, /var/spool/atjobs, or Windows at.exe.",
		Platforms:   []string{"Linux", "macOS", "Windows"},
	},
	"T1053.003": {
		ID: "T1053", SubID: "T1053.003", Name: "Scheduled Task/Job", SubName: "Cron",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may abuse cron to schedule code execution with elevated privileges.",
		Detection:   "Monitor crontab files, /etc/cron.d/, and cron.allow/cron.deny modifications.",
		Platforms:   []string{"Linux", "macOS"},
	},
	"T1053.005": {
		ID: "T1053", SubID: "T1053.005", Name: "Scheduled Task/Job", SubName: "Scheduled Task",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may abuse the Windows Task Scheduler to schedule programs for execution.",
		Detection:   "Monitor for schtasks.exe usage and Task Scheduler event logs.",
		Platforms:   []string{"Windows"},
	},
	"T1053.006": {
		ID: "T1053", SubID: "T1053.006", Name: "Scheduled Task/Job", SubName: "Systemd Timers",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may abuse systemd timers to schedule code execution at elevated privileges.",
		Detection:   "Monitor for new .timer unit files in systemd directories.",
		Platforms:   []string{"Linux"},
	},
	"T1053.007": {
		ID: "T1053", SubID: "T1053.007", Name: "Scheduled Task/Job", SubName: "Container Orchestration Job",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may abuse container orchestration schedulers to run containers with elevated privileges.",
		Detection:   "Monitor for Kubernetes CronJobs and privileged container deployments.",
		Platforms:   []string{"Containers"},
	},

	// T1078 - Valid Accounts
	"T1078": {
		ID: "T1078", Name: "Valid Accounts",
		Tactic: "Privilege Escalation", Severity: "CRITICAL",
		Description: "Adversaries may obtain and use credentials of existing accounts to gain higher-level access.",
		Detection:   "Monitor for unusual login patterns, credential access, and account permission changes.",
		Platforms:   []string{"Linux", "macOS", "Windows", "Azure AD", "SaaS"},
	},
	"T1078.001": {
		ID: "T1078", SubID: "T1078.001", Name: "Valid Accounts", SubName: "Default Accounts",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may use default accounts built into OS or applications that have preset passwords.",
		Detection:   "Monitor for login attempts to default/built-in accounts.",
		Platforms:   []string{"Linux", "macOS", "Windows"},
	},
	"T1078.002": {
		ID: "T1078", SubID: "T1078.002", Name: "Valid Accounts", SubName: "Domain Accounts",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may use domain account credentials to escalate privileges within a network.",
		Detection:   "Monitor for unusual domain account authentications and privilege changes.",
		Platforms:   []string{"Windows"},
	},
	"T1078.003": {
		ID: "T1078", SubID: "T1078.003", Name: "Valid Accounts", SubName: "Local Accounts",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may use local account credentials to escalate privileges on a system.",
		Detection:   "Monitor for local account creation, password changes, and privilege modifications.",
		Platforms:   []string{"Linux", "macOS", "Windows"},
	},
	"T1078.004": {
		ID: "T1078", SubID: "T1078.004", Name: "Valid Accounts", SubName: "Cloud Accounts",
		Tactic: "Privilege Escalation", Severity: "HIGH",
		Description: "Adversaries may use cloud account credentials to escalate privileges in cloud environments.",
		Detection:   "Monitor for unusual cloud API calls, role changes, and cross-account access.",
		Platforms:   []string{"Azure AD", "AWS", "GCP", "SaaS"},
	},

	// T1611 - Escape to Host
	"T1611": {
		ID: "T1611", Name: "Escape to Host",
		Tactic: "Privilege Escalation", Severity: "CRITICAL",
		Description: "Adversaries may break out of a container to gain access to the underlying host.",
		Detection:   "Monitor for privileged containers, host mounts, and container escape indicators.",
		Platforms:   []string{"Containers", "Linux"},
	},
}

// GetTechniquesByPlatform returns techniques applicable to a given platform
func GetTechniquesByPlatform(platform string) []Technique {
	var result []Technique
	for _, t := range PrivEscTechniques {
		for _, p := range t.Platforms {
			if p == platform {
				result = append(result, t)
				break
			}
		}
	}
	return result
}

// SeverityColor returns ANSI color code for severity
func SeverityColor(severity string) string {
	switch severity {
	case "CRITICAL":
		return "\033[1;31m" // Bold Red
	case "HIGH":
		return "\033[0;31m" // Red
	case "MEDIUM":
		return "\033[0;33m" // Yellow
	case "LOW":
		return "\033[0;36m" // Cyan
	case "INFO":
		return "\033[0;37m" // White
	default:
		return "\033[0m"
	}
}

// SeverityScore returns numeric score for severity
func SeverityScore(severity string) int {
	switch severity {
	case "CRITICAL":
		return 95
	case "HIGH":
		return 75
	case "MEDIUM":
		return 50
	case "LOW":
		return 25
	case "INFO":
		return 10
	default:
		return 0
	}
}
