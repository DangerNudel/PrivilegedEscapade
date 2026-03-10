package tui

import (
	"fmt"
	"os"
	"strings"

	"github.com/privesc-toolkit/internal/report"
)

const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
	Red     = "\033[0;31m"
	BRed    = "\033[1;31m"
	Green   = "\033[0;32m"
	BGreen  = "\033[1;32m"
	Yellow  = "\033[0;33m"
	Blue    = "\033[0;34m"
	Magenta = "\033[0;35m"
	Cyan    = "\033[0;36m"
	BCyan   = "\033[1;36m"
	White   = "\033[0;37m"
	BWhite  = "\033[1;37m"
)

type ModuleInfo struct {
	Name        string
	Description string
	Techniques  string
	Enabled     bool
}

// PrintBanner displays the tool banner
func PrintBanner() {
	banner := `
` + BRed + `    ╔═══════════════════════════════════════════════════════════════════╗` + Reset + `
` + BRed + `    ║` + Reset + BWhite + `   ____       _       ______              ___                      ` + BRed + `║` + Reset + `
` + BRed + `    ║` + Reset + BCyan + `  / __ \_____(_)   __/ ____/____________ _/ (_)___  ____            ` + BRed + `║` + Reset + `
` + BRed + `    ║` + Reset + BCyan + ` / /_/ / ___/ / | / / __/ / ___/ ___/ __  / / __  / __  \           ` + BRed + `║` + Reset + `
` + BRed + `    ║` + Reset + Cyan + `/ ____/ /  / /| |/ / /___(__  ) /__/ /_/ / / /_/ / /_/ /            ` + BRed + `║` + Reset + `
` + BRed + `    ║` + Reset + Cyan + `/_/   /_/  /_/ |___/_____/____/\___/\__,_/_/\__,_/\____/            ` + BRed + `║` + Reset + `
` + BRed + `    ║` + Reset + Yellow + `   ___                                            __              ` + BRed + `║` + Reset + `
` + BRed + `    ║` + Reset + Yellow + `  /   |  __________  ______________  _____  ____  / /_             ` + BRed + `║` + Reset + `
` + BRed + `    ║` + Reset + Yellow + ` / /| | / ___/ ___/ / _ \/ ___/ ___/ __ \/ ___/ / __/             ` + BRed + `║` + Reset + `
` + BRed + `    ║` + Reset + Yellow + `/ ___ |(__  |__  )/  __(__  |__  ) /_/ / /    / /_               ` + BRed + `║` + Reset + `
` + BRed + `    ║` + Reset + Yellow + `/_/  |_/____/____/ \___/____/____/\____/_/     \__/               ` + BRed + `║` + Reset + `
` + BRed + `    ║` + Reset + `                                                                   ` + BRed + `║` + Reset + `
` + BRed + `    ║` + Reset + `   ` + BWhite + `MITRE ATT&CK TA0004 - Privilege Escalation Assessment` + Reset + `          ` + BRed + `║` + Reset + `
` + BRed + `    ║` + Reset + `   ` + Dim + `Defensive Assessment & Detection Toolkit v1.0` + Reset + `                  ` + BRed + `║` + Reset + `
` + BRed + `    ║` + Reset + `   ` + Dim + `For authorized security assessment and education only` + Reset + `          ` + BRed + `║` + Reset + `
` + BRed + `    ╚═══════════════════════════════════════════════════════════════════╝` + Reset + `
`
	fmt.Print(banner)
}

// PrintMainMenu displays the main menu and returns the selection
func PrintMainMenu() string {
	fmt.Printf("\n%s┌─────────────────────────────────────────┐%s\n", Cyan, Reset)
	fmt.Printf("%s│%s  %sMAIN MENU%s                                %s│%s\n", Cyan, Reset, BWhite, Reset, Cyan, Reset)
	fmt.Printf("%s├─────────────────────────────────────────┤%s\n", Cyan, Reset)
	fmt.Printf("%s│%s                                         %s│%s\n", Cyan, Reset, Cyan, Reset)
	fmt.Printf("%s│%s  %s[1]%s  Run Full Assessment (All Modules)  %s│%s\n", Cyan, Reset, BGreen, Reset, Cyan, Reset)
	fmt.Printf("%s│%s  %s[2]%s  Select Individual Modules           %s│%s\n", Cyan, Reset, BGreen, Reset, Cyan, Reset)
	fmt.Printf("%s│%s  %s[3]%s  View Technique Coverage Map         %s│%s\n", Cyan, Reset, BGreen, Reset, Cyan, Reset)
	fmt.Printf("%s│%s  %s[4]%s  MITRE ATT&CK Reference Browser     %s│%s\n", Cyan, Reset, BGreen, Reset, Cyan, Reset)
	fmt.Printf("%s│%s  %s[5]%s  Export Settings                     %s│%s\n", Cyan, Reset, BGreen, Reset, Cyan, Reset)
	fmt.Printf("%s│%s  %s[Q]%s  Quit                                %s│%s\n", Cyan, Reset, Red, Reset, Cyan, Reset)
	fmt.Printf("%s│%s                                         %s│%s\n", Cyan, Reset, Cyan, Reset)
	fmt.Printf("%s└─────────────────────────────────────────┘%s\n", Cyan, Reset)
	fmt.Printf("\n%s[>]%s Select option: ", Cyan, Reset)

	var choice string
	fmt.Scanln(&choice)
	return strings.TrimSpace(strings.ToLower(choice))
}

// PrintModuleSelector displays module selection menu
func PrintModuleSelector(modules []ModuleInfo) []int {
	fmt.Printf("\n%s┌─────────────────────────────────────────────────────────────────┐%s\n", Cyan, Reset)
	fmt.Printf("%s│%s  %sSELECT ASSESSMENT MODULES%s                                       %s│%s\n", Cyan, Reset, BWhite, Reset, Cyan, Reset)
	fmt.Printf("%s├─────────────────────────────────────────────────────────────────┤%s\n", Cyan, Reset)

	for i, mod := range modules {
		status := Red + "[ ]" + Reset
		if mod.Enabled {
			status = Green + "[✓]" + Reset
		}
		fmt.Printf("%s│%s  %s %s[%d]%s %-42s %s%s%s  %s│%s\n",
			Cyan, Reset, status, Yellow, i+1, Reset, mod.Name, Dim, mod.Techniques, Reset, Cyan, Reset)
	}

	fmt.Printf("%s├─────────────────────────────────────────────────────────────────┤%s\n", Cyan, Reset)
	fmt.Printf("%s│%s  %s[A]%s Toggle All  %s[R]%s Run Selected  %s[B]%s Back                     %s│%s\n",
		Cyan, Reset, BGreen, Reset, BGreen, Reset, Yellow, Reset, Cyan, Reset)
	fmt.Printf("%s└─────────────────────────────────────────────────────────────────┘%s\n", Cyan, Reset)
	fmt.Printf("\n%s[>]%s Enter choice (number/A/R/B): ", Cyan, Reset)

	var choice string
	fmt.Scanln(&choice)
	choice = strings.TrimSpace(strings.ToLower(choice))

	switch choice {
	case "a":
		return []int{-1} // Toggle all
	case "r":
		return []int{-2} // Run
	case "b":
		return []int{-3} // Back
	default:
		var num int
		if _, err := fmt.Sscanf(choice, "%d", &num); err == nil && num >= 1 && num <= len(modules) {
			return []int{num - 1}
		}
	}
	return nil
}

// PrintExportMenu displays export options
func PrintExportMenu() (string, string) {
	fmt.Printf("\n%s┌─────────────────────────────────────────┐%s\n", Cyan, Reset)
	fmt.Printf("%s│%s  %sEXPORT SETTINGS%s                          %s│%s\n", Cyan, Reset, BWhite, Reset, Cyan, Reset)
	fmt.Printf("%s├─────────────────────────────────────────┤%s\n", Cyan, Reset)
	fmt.Printf("%s│%s  %s[1]%s  JSON Report                        %s│%s\n", Cyan, Reset, BGreen, Reset, Cyan, Reset)
	fmt.Printf("%s│%s  %s[2]%s  Markdown Report                    %s│%s\n", Cyan, Reset, BGreen, Reset, Cyan, Reset)
	fmt.Printf("%s│%s  %s[3]%s  Both Formats                       %s│%s\n", Cyan, Reset, BGreen, Reset, Cyan, Reset)
	fmt.Printf("%s│%s  %s[B]%s  Back                                %s│%s\n", Cyan, Reset, Yellow, Reset, Cyan, Reset)
	fmt.Printf("%s└─────────────────────────────────────────┘%s\n", Cyan, Reset)
	fmt.Printf("\n%s[>]%s Select format: ", Cyan, Reset)

	var choice string
	fmt.Scanln(&choice)
	choice = strings.TrimSpace(strings.ToLower(choice))

	switch choice {
	case "1":
		return "json", getOutputPath("json")
	case "2":
		return "markdown", getOutputPath("md")
	case "3":
		return "both", getOutputPath("")
	default:
		return "back", ""
	}
}

func getOutputPath(ext string) string {
	defaultBase := fmt.Sprintf("privesc_assessment_%s", strings.ReplaceAll(
		strings.Split(fmt.Sprintf("%v", os.Getenv("HOSTNAME")), ".")[0], " ", "_"))
	if ext != "" {
		return defaultBase + "." + ext
	}
	return defaultBase
}

// PrintProgress displays a progress indicator
func PrintProgress(current, total int, moduleName string) {
	pct := float64(current) / float64(total) * 100
	barWidth := 30
	filled := int(float64(barWidth) * float64(current) / float64(total))

	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	fmt.Printf("\r%s[%s]%s %s%.0f%%%s %s[%d/%d]%s %s%-40s%s",
		Cyan, bar, Reset, BGreen, pct, Reset, Dim, current, total, Reset,
		Yellow, moduleName, Reset)

	if current == total {
		fmt.Println()
	}
}

// PrintTechReference displays MITRE technique reference
func PrintTechReference(techniques map[string]string) {
	fmt.Printf("\n%s═══════════════════════════════════════════════════════════════════%s\n", BWhite, Reset)
	fmt.Printf("%s  MITRE ATT&CK TA0004 - Privilege Escalation Technique Reference%s\n", BWhite, Reset)
	fmt.Printf("%s═══════════════════════════════════════════════════════════════════%s\n\n", BWhite, Reset)

	parents := []struct {
		id   string
		name string
	}{
		{"T1548", "Abuse Elevation Control Mechanism"},
		{"T1134", "Access Token Manipulation"},
		{"T1547", "Boot or Logon Autostart Execution"},
		{"T1037", "Boot or Logon Initialization Scripts"},
		{"T1543", "Create or Modify System Process"},
		{"T1484", "Domain or Tenant Policy Modification"},
		{"T1546", "Event Triggered Execution"},
		{"T1068", "Exploitation for Privilege Escalation"},
		{"T1574", "Hijack Execution Flow"},
		{"T1055", "Process Injection"},
		{"T1053", "Scheduled Task/Job"},
		{"T1078", "Valid Accounts"},
		{"T1611", "Escape to Host"},
	}

	for _, p := range parents {
		fmt.Printf("  %s%-8s%s %s%s%s\n", BCyan, p.id, Reset, Bold, p.name, Reset)
		if desc, ok := techniques[p.id]; ok {
			fmt.Printf("           %s%s%s\n", Dim, desc, Reset)
		}
		fmt.Println()
	}

	fmt.Printf("\n%s[>]%s Press Enter to return... ", Cyan, Reset)
	fmt.Scanln()
}

// PrintFindingCount shows a quick count after assessment
func PrintFindingCount(modName string, count int) {
	color := Green
	if count > 0 {
		color = Yellow
	}
	if count > 5 {
		color = Red
	}
	fmt.Printf("  %s✓%s %-45s %s%d findings%s\n", Green, Reset, modName, color, count, Reset)
}

// PrintScanComplete shows scan completion message
func PrintScanComplete() {
	fmt.Printf("\n%s  ╔══════════════════════════════════════╗%s\n", Green, Reset)
	fmt.Printf("%s  ║%s   %s✓ ASSESSMENT COMPLETE%s                %s║%s\n", Green, Reset, BGreen, Reset, Green, Reset)
	fmt.Printf("%s  ╚══════════════════════════════════════╝%s\n", Green, Reset)
}

// PrintExportSuccess shows successful export
func PrintExportSuccess(format, path string) {
	fmt.Printf("\n%s  ✓%s Report exported: %s%s%s (%s)\n", Green, Reset, Bold, path, Reset, format)
}

// PrintDisclaimer shows the usage disclaimer
func PrintDisclaimer() {
	fmt.Printf("\n%s┌─────────────────────────────────────────────────────────────────┐%s\n", Yellow, Reset)
	fmt.Printf("%s│%s  %s⚠  AUTHORIZED USE ONLY%s                                          %s│%s\n", Yellow, Reset, Bold+Yellow, Reset, Yellow, Reset)
	fmt.Printf("%s│%s                                                                 %s│%s\n", Yellow, Reset, Yellow, Reset)
	fmt.Printf("%s│%s  This tool performs DETECTION and ASSESSMENT only.              %s│%s\n", Yellow, Reset, Yellow, Reset)
	fmt.Printf("%s│%s  It identifies potential privilege escalation vectors but       %s│%s\n", Yellow, Reset, Yellow, Reset)
	fmt.Printf("%s│%s  does NOT exploit them. Use only on authorized systems.         %s│%s\n", Yellow, Reset, Yellow, Reset)
	fmt.Printf("%s│%s                                                                 %s│%s\n", Yellow, Reset, Yellow, Reset)
	fmt.Printf("%s│%s  Coverage: MITRE ATT&CK TA0004 Privilege Escalation            %s│%s\n", Yellow, Reset, Yellow, Reset)
	fmt.Printf("%s│%s  13 Parent Techniques | 60+ Sub-Techniques                     %s│%s\n", Yellow, Reset, Yellow, Reset)
	fmt.Printf("%s└─────────────────────────────────────────────────────────────────┘%s\n", Yellow, Reset)

	fmt.Printf("\n%s[>]%s Press Enter to continue... ", Cyan, Reset)
	fmt.Scanln()
}

// ConfirmAction asks for confirmation
func ConfirmAction(prompt string) bool {
	fmt.Printf("%s[?]%s %s (y/N): ", Yellow, Reset, prompt)
	var resp string
	fmt.Scanln(&resp)
	resp = strings.TrimSpace(strings.ToLower(resp))
	return resp == "y" || resp == "yes"
}

// PrintError displays an error message
func PrintError(msg string) {
	fmt.Printf("%s[✗]%s %s\n", Red, Reset, msg)
}

// ClearScreen clears the terminal
func ClearScreen() {
	fmt.Print("\033[2J\033[H")
}

// PrintReportOptions asks what to do after assessment
func PrintReportOptions() string {
	fmt.Printf("\n%s┌─────────────────────────────────────────┐%s\n", Cyan, Reset)
	fmt.Printf("%s│%s  %sPOST-ASSESSMENT OPTIONS%s                  %s│%s\n", Cyan, Reset, BWhite, Reset, Cyan, Reset)
	fmt.Printf("%s├─────────────────────────────────────────┤%s\n", Cyan, Reset)
	fmt.Printf("%s│%s  %s[1]%s  View Detailed Findings              %s│%s\n", Cyan, Reset, BGreen, Reset, Cyan, Reset)
	fmt.Printf("%s│%s  %s[2]%s  View Technique Heatmap              %s│%s\n", Cyan, Reset, BGreen, Reset, Cyan, Reset)
	fmt.Printf("%s│%s  %s[3]%s  Export JSON Report                  %s│%s\n", Cyan, Reset, BGreen, Reset, Cyan, Reset)
	fmt.Printf("%s│%s  %s[4]%s  Export Markdown Report              %s│%s\n", Cyan, Reset, BGreen, Reset, Cyan, Reset)
	fmt.Printf("%s│%s  %s[5]%s  Export All Formats                  %s│%s\n", Cyan, Reset, BGreen, Reset, Cyan, Reset)
	fmt.Printf("%s│%s  %s[B]%s  Back to Main Menu                   %s│%s\n", Cyan, Reset, Yellow, Reset, Cyan, Reset)
	fmt.Printf("%s└─────────────────────────────────────────┘%s\n", Cyan, Reset)
	fmt.Printf("\n%s[>]%s Select option: ", Cyan, Reset)

	var choice string
	fmt.Scanln(&choice)
	return strings.TrimSpace(strings.ToLower(choice))
}

// HandleExport handles exporting reports
func HandleExport(data report.ReportData, format string) {
	hostname, _ := os.Hostname()
	base := fmt.Sprintf("privesc_%s", hostname)

	switch format {
	case "json", "1", "3":
		path := base + ".json"
		if err := report.ExportJSON(data, path); err != nil {
			PrintError(fmt.Sprintf("JSON export failed: %v", err))
		} else {
			PrintExportSuccess("JSON", path)
		}
		if format != "3" && format != "both" {
			break
		}
		fallthrough
	case "markdown", "md", "2", "4":
		path := base + ".md"
		if err := report.ExportMarkdown(data, path); err != nil {
			PrintError(fmt.Sprintf("Markdown export failed: %v", err))
		} else {
			PrintExportSuccess("Markdown", path)
		}
	case "both", "5":
		jsonPath := base + ".json"
		mdPath := base + ".md"
		if err := report.ExportJSON(data, jsonPath); err != nil {
			PrintError(fmt.Sprintf("JSON export failed: %v", err))
		} else {
			PrintExportSuccess("JSON", jsonPath)
		}
		if err := report.ExportMarkdown(data, mdPath); err != nil {
			PrintError(fmt.Sprintf("Markdown export failed: %v", err))
		} else {
			PrintExportSuccess("Markdown", mdPath)
		}
	}
}
