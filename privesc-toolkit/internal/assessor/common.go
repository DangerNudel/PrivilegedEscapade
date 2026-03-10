package assessor

import (
	"github.com/privesc-toolkit/internal/mitre"
)

// AssessmentResult holds the results of a single check
type AssessmentResult struct {
	ModuleName  string
	Findings    []mitre.Finding
	Errors      []string
	Duration    string
}

// Module defines the interface for all assessment modules
type Module interface {
	Name() string
	Description() string
	TechniqueIDs() []string
	Run() AssessmentResult
}

// SummaryStats holds aggregate statistics
type SummaryStats struct {
	TotalChecks   int
	TotalFindings int
	Critical      int
	High          int
	Medium        int
	Low           int
	Info          int
}

// ComputeStats computes summary statistics from results
func ComputeStats(results []AssessmentResult) SummaryStats {
	stats := SummaryStats{}
	for _, r := range results {
		stats.TotalChecks++
		stats.TotalFindings += len(r.Findings)
		for _, f := range r.Findings {
			switch f.Technique.Severity {
			case "CRITICAL":
				stats.Critical++
			case "HIGH":
				stats.High++
			case "MEDIUM":
				stats.Medium++
			case "LOW":
				stats.Low++
			case "INFO":
				stats.Info++
			}
		}
	}
	return stats
}
