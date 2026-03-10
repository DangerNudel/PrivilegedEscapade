package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/privesc-toolkit/internal/assessor"
	"github.com/privesc-toolkit/internal/mitre"
	"github.com/privesc-toolkit/internal/report"
	"github.com/privesc-toolkit/internal/tui"
)

const version = "1.0.0"

// All available assessment modules
func getAllModules() []assessor.Module {
	return []assessor.Module{
		&assessor.SUIDBinaryModule{},
		&assessor.SudoModule{},
		&assessor.KernelModule{},
		&assessor.ScheduledTaskModule{},
		&assessor.ServiceModule{},
		&assessor.PathHijackModule{},
		&assessor.ContainerModule{},
		&assessor.AccountModule{},
		&assessor.ShellEnvModule{},
	}
}

func getModuleInfoList(modules []assessor.Module, enabled []bool) []tui.ModuleInfo {
	var infos []tui.ModuleInfo
	for i, m := range modules {
		infos = append(infos, tui.ModuleInfo{
			Name:        m.Name(),
			Description: m.Description(),
			Techniques:  fmt.Sprintf("%v", m.TechniqueIDs()),
			Enabled:     enabled[i],
		})
	}
	return infos
}

func runModules(modules []assessor.Module, enabled []bool) []assessor.AssessmentResult {
	var results []assessor.AssessmentResult
	total := 0
	for _, e := range enabled {
		if e {
			total++
		}
	}

	current := 0
	for i, mod := range modules {
		if !enabled[i] {
			continue
		}
		current++
		tui.PrintProgress(current, total, mod.Name())
		result := mod.Run()
		results = append(results, result)
		tui.PrintFindingCount(mod.Name(), len(result.Findings))
	}
	return results
}

func interactiveMode() {
	tui.ClearScreen()
	tui.PrintBanner()
	tui.PrintDisclaimer()

	modules := getAllModules()
	enabled := make([]bool, len(modules))
	for i := range enabled {
		enabled[i] = true // All enabled by default
	}

	var lastResults []assessor.AssessmentResult
	var lastReportData report.ReportData

	for {
		choice := tui.PrintMainMenu()

		switch choice {
		case "1": // Full assessment
			tui.ClearScreen()
			fmt.Printf("\n%s  ═══ Running Full Assessment ═══%s\n\n", tui.BWhite, tui.Reset)

			startTime := time.Now()
			// Enable all
			for i := range enabled {
				enabled[i] = true
			}
			lastResults = runModules(modules, enabled)
			tui.PrintScanComplete()

			lastReportData = report.NewReportData(lastResults, startTime)
			report.PrintSummaryBanner(lastReportData)

			// Post-assessment menu
			postAssessmentLoop(lastReportData)

		case "2": // Select modules
			for {
				tui.ClearScreen()
				infos := getModuleInfoList(modules, enabled)
				selection := tui.PrintModuleSelector(infos)

				if len(selection) == 0 {
					continue
				}
				if selection[0] == -1 { // Toggle all
					allEnabled := true
					for _, e := range enabled {
						if !e {
							allEnabled = false
							break
						}
					}
					for i := range enabled {
						enabled[i] = !allEnabled
					}
					continue
				}
				if selection[0] == -2 { // Run selected
					tui.ClearScreen()
					fmt.Printf("\n%s  ═══ Running Selected Modules ═══%s\n\n", tui.BWhite, tui.Reset)

					startTime := time.Now()
					lastResults = runModules(modules, enabled)
					tui.PrintScanComplete()

					lastReportData = report.NewReportData(lastResults, startTime)
					report.PrintSummaryBanner(lastReportData)
					postAssessmentLoop(lastReportData)
					break
				}
				if selection[0] == -3 { // Back
					break
				}
				// Toggle individual module
				if selection[0] >= 0 && selection[0] < len(enabled) {
					enabled[selection[0]] = !enabled[selection[0]]
				}
			}

		case "3": // Technique coverage
			tui.ClearScreen()
			if len(lastResults) > 0 {
				report.PrintTechniqueHeatmap(lastReportData)
			} else {
				fmt.Printf("\n%s  No assessment data. Run an assessment first.%s\n", tui.Yellow, tui.Reset)
			}
			fmt.Printf("\n%s[>]%s Press Enter to continue... ", tui.Cyan, tui.Reset)
			fmt.Scanln()

		case "4": // MITRE reference
			tui.ClearScreen()
			techDescs := make(map[string]string)
			for id, t := range mitre.PrivEscTechniques {
				if t.SubID == "" { // Only parent techniques
					techDescs[id] = t.Description
				}
			}
			tui.PrintTechReference(techDescs)

		case "5": // Export settings
			if len(lastResults) == 0 {
				fmt.Printf("\n%s  No assessment data. Run an assessment first.%s\n", tui.Yellow, tui.Reset)
				fmt.Printf("\n%s[>]%s Press Enter to continue... ", tui.Cyan, tui.Reset)
				fmt.Scanln()
				continue
			}
			format, _ := tui.PrintExportMenu()
			if format != "back" {
				tui.HandleExport(lastReportData, format)
				fmt.Printf("\n%s[>]%s Press Enter to continue... ", tui.Cyan, tui.Reset)
				fmt.Scanln()
			}

		case "q", "quit", "exit":
			fmt.Printf("\n%s  Goodbye.%s\n\n", tui.Dim, tui.Reset)
			return
		}
	}
}

func postAssessmentLoop(data report.ReportData) {
	for {
		choice := tui.PrintReportOptions()
		switch choice {
		case "1":
			report.PrintDetailedResults(data)
			fmt.Printf("\n%s[>]%s Press Enter to continue... ", tui.Cyan, tui.Reset)
			fmt.Scanln()
		case "2":
			report.PrintTechniqueHeatmap(data)
			fmt.Printf("\n%s[>]%s Press Enter to continue... ", tui.Cyan, tui.Reset)
			fmt.Scanln()
		case "3":
			tui.HandleExport(data, "json")
			fmt.Printf("\n%s[>]%s Press Enter to continue... ", tui.Cyan, tui.Reset)
			fmt.Scanln()
		case "4":
			tui.HandleExport(data, "markdown")
			fmt.Printf("\n%s[>]%s Press Enter to continue... ", tui.Cyan, tui.Reset)
			fmt.Scanln()
		case "5":
			tui.HandleExport(data, "both")
			fmt.Printf("\n%s[>]%s Press Enter to continue... ", tui.Cyan, tui.Reset)
			fmt.Scanln()
		case "b", "back":
			return
		}
	}
}

func cliMode(outputJSON, outputMD string, moduleFilter string) {
	tui.PrintBanner()

	modules := getAllModules()
	enabled := make([]bool, len(modules))

	if moduleFilter == "all" {
		for i := range enabled {
			enabled[i] = true
		}
	} else {
		// Parse comma-separated module indices
		for i := range enabled {
			enabled[i] = true // Default all for CLI
		}
	}

	startTime := time.Now()
	fmt.Printf("\n  Running assessment...\n\n")
	results := runModules(modules, enabled)
	tui.PrintScanComplete()

	data := report.NewReportData(results, startTime)
	report.PrintSummaryBanner(data)
	report.PrintDetailedResults(data)
	report.PrintTechniqueHeatmap(data)

	if outputJSON != "" {
		if err := report.ExportJSON(data, outputJSON); err != nil {
			tui.PrintError(fmt.Sprintf("JSON export failed: %v", err))
		} else {
			tui.PrintExportSuccess("JSON", outputJSON)
		}
	}

	if outputMD != "" {
		if err := report.ExportMarkdown(data, outputMD); err != nil {
			tui.PrintError(fmt.Sprintf("Markdown export failed: %v", err))
		} else {
			tui.PrintExportSuccess("Markdown", outputMD)
		}
	}
}

func main() {
	// CLI flags
	interactive := flag.Bool("i", false, "Interactive TUI mode")
	outputJSON := flag.String("json", "", "Export JSON report to file")
	outputMD := flag.String("md", "", "Export Markdown report to file")
	moduleFilter := flag.String("modules", "all", "Comma-separated module list or 'all'")
	showVersion := flag.Bool("version", false, "Show version")
	nonInteractive := flag.Bool("auto", false, "Non-interactive mode (run all modules, output to terminal)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
PrivEscalation Assessor - MITRE ATT&CK TA0004 Assessment Toolkit v%s

USAGE:
  privesc-assess                   Interactive TUI mode (default)
  privesc-assess -auto             Non-interactive full scan
  privesc-assess -auto -json out.json -md out.md

FLAGS:
`, version)
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
MODULES:
  1. SUID/SGID Binary Analysis       (T1548, T1548.001)
  2. Sudo Configuration Analysis      (T1548, T1548.003)
  3. Kernel & Exploit Vector Analysis  (T1068)
  4. Scheduled Task & Cron Analysis    (T1053, T1053.002, T1053.003, T1053.006)
  5. System Service & Daemon Analysis  (T1543, T1543.002)
  6. Execution Flow Hijacking          (T1574, T1574.006, T1574.007)
  7. Container Escape & Environment    (T1611)
  8. Account & Credential Analysis     (T1078, T1078.001, T1078.003)
  9. Shell & Event-Triggered Execution (T1546, T1546.004, T1547)

EXAMPLES:
  privesc-assess                      # Interactive mode
  privesc-assess -auto                # Full scan with terminal output
  privesc-assess -auto -json report.json
  privesc-assess -auto -json report.json -md report.md`)
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("PrivEscalation Assessor v%s\n", version)
		return
	}

	if *nonInteractive {
		cliMode(*outputJSON, *outputMD, *moduleFilter)
		return
	}

	// Default to interactive mode
	if *interactive || (!*nonInteractive && *outputJSON == "" && *outputMD == "") {
		interactiveMode()
		return
	}

	// If only export flags given, run in CLI mode
	cliMode(*outputJSON, *outputMD, *moduleFilter)
}
