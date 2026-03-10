package report

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/privesc-toolkit/internal/assessor"
	"github.com/privesc-toolkit/internal/mitre"
)

const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Red     = "\033[0;31m"
	BRed    = "\033[1;31m"
	Green   = "\033[0;32m"
	Yellow  = "\033[0;33m"
	Blue    = "\033[0;34m"
	Magenta = "\033[0;35m"
	Cyan    = "\033[0;36m"
	White   = "\033[0;37m"
	BWhite  = "\033[1;37m"
	Dim     = "\033[2m"
	BgRed   = "\033[41m"
	BgGreen = "\033[42m"
	BgYellow = "\033[43m"
)

// ReportData contains all data needed for report generation
type ReportData struct {
	Results    []assessor.AssessmentResult
	Stats      assessor.SummaryStats
	StartTime  time.Time
	EndTime    time.Time
	Hostname   string
	OS         string
	Arch       string
	Username   string
}

// NewReportData creates report data from assessment results
func NewReportData(results []assessor.AssessmentResult, startTime time.Time) ReportData {
	hostname, _ := os.Hostname()
	u, _ := user.Current()
	username := "unknown"
	if u != nil {
		username = u.Username
	}

	return ReportData{
		Results:   results,
		Stats:     assessor.ComputeStats(results),
		StartTime: startTime,
		EndTime:   time.Now(),
		Hostname:  hostname,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Username:  username,
	}
}

// PrintSummaryBanner prints the assessment summary banner
func PrintSummaryBanner(data ReportData) {
	w := 72
	line := strings.Repeat("═", w)
	fmt.Printf("\n%s╔%s╗%s\n", Cyan, line, Reset)
	centerPrint(w, "PRIVILEGE ESCALATION ASSESSMENT REPORT", BWhite)
	centerPrint(w, "MITRE ATT&CK TA0004 Coverage", Dim)
	fmt.Printf("%s╠%s╣%s\n", Cyan, line, Reset)

	infoPrint(w, "Host", data.Hostname)
	infoPrint(w, "OS / Arch", fmt.Sprintf("%s / %s", data.OS, data.Arch))
	infoPrint(w, "User", data.Username)
	infoPrint(w, "Date", data.StartTime.Format("2006-01-02 15:04:05 MST"))
	infoPrint(w, "Duration", data.EndTime.Sub(data.StartTime).Round(time.Millisecond).String())

	fmt.Printf("%s╠%s╣%s\n", Cyan, line, Reset)

	// Risk score bar
	total := data.Stats.TotalFindings
	centerPrint(w, fmt.Sprintf("Total Findings: %d", total), BWhite)
	fmt.Printf("%s║%s  ", Cyan, Reset)
	if data.Stats.Critical > 0 {
		fmt.Printf("%s%s CRITICAL: %-3d %s ", BgRed, BWhite, data.Stats.Critical, Reset)
	}
	if data.Stats.High > 0 {
		fmt.Printf("%s HIGH: %-3d %s ", Red, data.Stats.High, Reset)
	}
	if data.Stats.Medium > 0 {
		fmt.Printf("%s MEDIUM: %-3d %s ", Yellow, data.Stats.Medium, Reset)
	}
	if data.Stats.Low > 0 {
		fmt.Printf("%s LOW: %-3d %s ", Cyan, data.Stats.Low, Reset)
	}
	if data.Stats.Info > 0 {
		fmt.Printf("%s INFO: %-3d %s ", Dim, data.Stats.Info, Reset)
	}
	// Pad to box width
	fmt.Printf("%*s%s║%s\n", 0, "", Cyan, Reset)

	fmt.Printf("%s╚%s╝%s\n\n", Cyan, line, Reset)
}

func centerPrint(w int, text, color string) {
	pad := (w - len(text)) / 2
	if pad < 0 {
		pad = 0
	}
	fmt.Printf("%s║%s%*s%s%s%*s%s║%s\n",
		Cyan, Reset, pad, "", color, text, w-pad-len(text), "", Cyan, Reset)
}

func infoPrint(w int, label, value string) {
	content := fmt.Sprintf("  %s%-12s%s %s", Bold, label+":", Reset, value)
	// Account for ANSI codes in padding
	visLen := len(label) + 2 + 1 + 1 + len(value)
	pad := w - visLen
	if pad < 0 {
		pad = 0
	}
	fmt.Printf("%s║%s%s%*s%s║%s\n", Cyan, Reset, content, pad, "", Cyan, Reset)
}

// PrintDetailedResults prints detailed findings grouped by module
func PrintDetailedResults(data ReportData) {
	for _, r := range data.Results {
		if len(r.Findings) == 0 {
			continue
		}

		fmt.Printf("\n%s┌─ %s%s %s(%s)%s\n", Blue, BWhite, r.ModuleName, Dim, r.Duration, Reset)

		// Sort findings by risk score (descending)
		sorted := make([]mitre.Finding, len(r.Findings))
		copy(sorted, r.Findings)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].RiskScore > sorted[j].RiskScore
		})

		for i, f := range sorted {
			prefix := "├"
			if i == len(sorted)-1 {
				prefix = "└"
			}

			sevColor := mitre.SeverityColor(f.Technique.Severity)
			techID := f.Technique.ID
			if f.Technique.SubID != "" {
				techID = f.Technique.SubID
			}

			fmt.Printf("%s%s──%s [%s%-8s%s] [%s] %s\n",
				Blue, prefix, Reset,
				sevColor, f.Technique.Severity, Reset,
				techID, f.Detail)

			if f.Evidence != "" {
				fmt.Printf("%s│    %sEvidence:%s %s\n", Blue, Dim, Reset, truncateReport(f.Evidence, 120))
			}
			if f.Remediation != "" {
				fmt.Printf("%s│    %sFix:%s %s%s%s\n", Blue, Dim, Reset, Green, truncateReport(f.Remediation, 120), Reset)
			}
		}
	}
}

// PrintTechniqueHeatmap prints a technique coverage heatmap
func PrintTechniqueHeatmap(data ReportData) {
	fmt.Printf("\n%s═══ MITRE ATT&CK TA0004 Technique Heatmap ═══%s\n\n", BWhite, Reset)

	// Collect findings per technique
	techMap := make(map[string][]mitre.Finding)
	for _, r := range data.Results {
		for _, f := range r.Findings {
			id := f.Technique.ID
			if f.Technique.SubID != "" {
				id = f.Technique.SubID
			}
			techMap[id] = append(techMap[id], f)
		}
	}

	// Get all parent techniques sorted
	parents := []string{"T1548", "T1134", "T1547", "T1037", "T1543", "T1484", "T1546", "T1068", "T1574", "T1055", "T1053", "T1078", "T1611"}

	for _, pid := range parents {
		tech, ok := mitre.PrivEscTechniques[pid]
		if !ok {
			continue
		}

		findings := techMap[pid]
		indicator := "  "
		if len(findings) > 0 {
			maxSev := getMaxSeverity(findings)
			indicator = sevIcon(maxSev)
		}

		fmt.Printf("  %s %s%-8s%s %s\n", indicator, Bold, pid, Reset, tech.Name)

		// Print sub-techniques
		for id, subTech := range mitre.PrivEscTechniques {
			if subTech.ID == pid && id != pid && subTech.SubID != "" {
				subFindings := techMap[id]
				subIndicator := "  "
				if len(subFindings) > 0 {
					maxSev := getMaxSeverity(subFindings)
					subIndicator = sevIcon(maxSev)
				}
				subName := subTech.SubName
				if subName == "" {
					subName = subTech.Name
				}
				fmt.Printf("    %s %s%-12s%s %s %s(%d findings)%s\n",
					subIndicator, Dim, id, Reset, subName, Dim, len(subFindings), Reset)
			}
		}
	}

	fmt.Printf("\n  %sLegend:%s %s●%s CRITICAL  %s●%s HIGH  %s●%s MEDIUM  %s●%s LOW  %s●%s INFO  %s·%s Not checked\n\n",
		Dim, Reset, BRed, Reset, Red, Reset, Yellow, Reset, Cyan, Reset, Dim, Reset, Dim, Reset)
}

func getMaxSeverity(findings []mitre.Finding) string {
	severityOrder := map[string]int{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
	maxSev := "INFO"
	maxScore := 0
	for _, f := range findings {
		if score, ok := severityOrder[f.Technique.Severity]; ok && score > maxScore {
			maxScore = score
			maxSev = f.Technique.Severity
		}
	}
	return maxSev
}

func sevIcon(severity string) string {
	switch severity {
	case "CRITICAL":
		return BRed + "●" + Reset
	case "HIGH":
		return Red + "●" + Reset
	case "MEDIUM":
		return Yellow + "●" + Reset
	case "LOW":
		return Cyan + "●" + Reset
	case "INFO":
		return Dim + "●" + Reset
	default:
		return Dim + "·" + Reset
	}
}

// ExportJSON exports the report as JSON
func ExportJSON(data ReportData, filepath string) error {
	type JSONFinding struct {
		TechniqueID string `json:"technique_id"`
		Technique   string `json:"technique"`
		SubTechnique string `json:"sub_technique,omitempty"`
		Severity    string `json:"severity"`
		Detail      string `json:"detail"`
		Evidence    string `json:"evidence"`
		Remediation string `json:"remediation"`
		RiskScore   int    `json:"risk_score"`
	}

	type JSONModule struct {
		Module   string        `json:"module"`
		Duration string        `json:"duration"`
		Findings []JSONFinding `json:"findings"`
	}

	type JSONReport struct {
		Meta struct {
			Hostname  string `json:"hostname"`
			OS        string `json:"os"`
			Arch      string `json:"arch"`
			User      string `json:"user"`
			Timestamp string `json:"timestamp"`
			Duration  string `json:"duration"`
		} `json:"meta"`
		Summary struct {
			Total    int `json:"total_findings"`
			Critical int `json:"critical"`
			High     int `json:"high"`
			Medium   int `json:"medium"`
			Low      int `json:"low"`
			Info     int `json:"info"`
		} `json:"summary"`
		Modules []JSONModule `json:"modules"`
	}

	report := JSONReport{}
	report.Meta.Hostname = data.Hostname
	report.Meta.OS = data.OS
	report.Meta.Arch = data.Arch
	report.Meta.User = data.Username
	report.Meta.Timestamp = data.StartTime.Format(time.RFC3339)
	report.Meta.Duration = data.EndTime.Sub(data.StartTime).String()
	report.Summary.Total = data.Stats.TotalFindings
	report.Summary.Critical = data.Stats.Critical
	report.Summary.High = data.Stats.High
	report.Summary.Medium = data.Stats.Medium
	report.Summary.Low = data.Stats.Low
	report.Summary.Info = data.Stats.Info

	for _, r := range data.Results {
		mod := JSONModule{Module: r.ModuleName, Duration: r.Duration}
		for _, f := range r.Findings {
			jf := JSONFinding{
				TechniqueID: f.Technique.ID,
				Technique:   f.Technique.Name,
				Severity:    f.Technique.Severity,
				Detail:      f.Detail,
				Evidence:    f.Evidence,
				Remediation: f.Remediation,
				RiskScore:   f.RiskScore,
			}
			if f.Technique.SubID != "" {
				jf.TechniqueID = f.Technique.SubID
				jf.SubTechnique = f.Technique.SubName
			}
			mod.Findings = append(mod.Findings, jf)
		}
		report.Modules = append(report.Modules, mod)
	}

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath, jsonData, 0644)
}

// ExportMarkdown exports the report as Markdown
func ExportMarkdown(data ReportData, filepath string) error {
	var sb strings.Builder

	sb.WriteString("# Privilege Escalation Assessment Report\n\n")
	sb.WriteString(fmt.Sprintf("**Host:** %s  \n", data.Hostname))
	sb.WriteString(fmt.Sprintf("**OS/Arch:** %s/%s  \n", data.OS, data.Arch))
	sb.WriteString(fmt.Sprintf("**User:** %s  \n", data.Username))
	sb.WriteString(fmt.Sprintf("**Date:** %s  \n", data.StartTime.Format("2006-01-02 15:04:05 MST")))
	sb.WriteString(fmt.Sprintf("**Duration:** %s  \n\n", data.EndTime.Sub(data.StartTime).Round(time.Millisecond)))

	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("| Severity | Count |\n|---|---|\n"))
	sb.WriteString(fmt.Sprintf("| CRITICAL | %d |\n", data.Stats.Critical))
	sb.WriteString(fmt.Sprintf("| HIGH | %d |\n", data.Stats.High))
	sb.WriteString(fmt.Sprintf("| MEDIUM | %d |\n", data.Stats.Medium))
	sb.WriteString(fmt.Sprintf("| LOW | %d |\n", data.Stats.Low))
	sb.WriteString(fmt.Sprintf("| INFO | %d |\n", data.Stats.Info))
	sb.WriteString(fmt.Sprintf("| **Total** | **%d** |\n\n", data.Stats.TotalFindings))

	for _, r := range data.Results {
		if len(r.Findings) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("## %s\n\n", r.ModuleName))

		for _, f := range r.Findings {
			techID := f.Technique.ID
			if f.Technique.SubID != "" {
				techID = f.Technique.SubID
			}
			sb.WriteString(fmt.Sprintf("### [%s] %s - %s\n\n", f.Technique.Severity, techID, f.Detail))
			if f.Evidence != "" {
				sb.WriteString(fmt.Sprintf("**Evidence:** %s  \n", f.Evidence))
			}
			if f.Remediation != "" {
				sb.WriteString(fmt.Sprintf("**Remediation:** %s  \n", f.Remediation))
			}
			sb.WriteString(fmt.Sprintf("**Risk Score:** %d/100  \n\n", f.RiskScore))
		}
	}

	return os.WriteFile(filepath, []byte(sb.String()), 0644)
}

func truncateReport(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
