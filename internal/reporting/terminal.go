package reporting

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/springhawk/springhawk/pkg/models"
)

var (
	colorCritical = color.New(color.FgRed, color.Bold)
	colorHigh     = color.New(color.FgYellow, color.Bold)
	colorMedium   = color.New(color.FgYellow)
	colorLow      = color.New(color.FgCyan)
	colorInfo     = color.New(color.FgWhite)
	colorGreen    = color.New(color.FgGreen, color.Bold)
	colorDim      = color.New(color.Faint)
	colorBold     = color.New(color.Bold)
)

const banner = `
 ___            _             _   _               _
/ __|_ __ _ _ _(_)_ _  __ _ | | | |__ ___ __ ___| |__
\__ \ '_ \ '_| | ' \/ _' || |_| / _' \ V  V /| / /
|___/ .__/_| |_|_||_\__, | \___/\__,_|\_/\_/ |_\_\
    |_|              |___/
                          Spring Boot Security Scanner v1.0
`

func PrintBanner(w io.Writer) {
	colorCritical.Fprintln(w, banner)
}

func PrintFinding(w io.Writer, f *models.Finding) {
	sev := severityColor(f.Severity)
	sev.Fprintf(w, "\n[%s] ", f.Severity)
	colorBold.Fprintf(w, "%s\n", f.Title)
	colorDim.Fprintf(w, "  Module  : %s\n", f.ModuleID)
	if f.URL != "" {
		fmt.Fprintf(w, "  URL     : %s\n", f.URL)
	}
	if f.Endpoint != "" && f.Endpoint != f.URL {
		fmt.Fprintf(w, "  Endpoint: %s\n", f.Endpoint)
	}
	if len(f.CVEIDs) > 0 {
		colorHigh.Fprintf(w, "  CVE     : %s\n", strings.Join(f.CVEIDs, ", "))
	}
	colorDim.Fprintf(w, "  CVSS    : %.1f\n", f.CVSS)
	fmt.Fprintf(w, "  Evidence: %s\n", f.Evidence)
	if f.Remediation != "" {
		colorGreen.Fprintf(w, "  Fix     : %s\n", f.Remediation)
	}
	if f.IsExploited {
		colorCritical.Fprintf(w, "  *** EXPLOITED ***\n")
		for k, v := range f.ExtraData {
			colorCritical.Fprintf(w, "  %s: %s\n", k, v)
		}
	}
}

func PrintScanSummary(w io.Writer, result *models.ScanResult) {
	colorBold.Fprintf(w, "\n%s\n", strings.Repeat("─", 60))
	colorBold.Fprintf(w, "SCAN SUMMARY\n")
	colorDim.Fprintf(w, "%s\n", strings.Repeat("─", 60))
	fmt.Fprintf(w, "Target    : %s\n", result.Target.BaseURL)
	fmt.Fprintf(w, "SpringBoot: %v (confidence: %d%%)\n", result.IsSpringBoot, confidenceOrZero(result.Fingerprint))
	fmt.Fprintf(w, "Duration  : %s\n", result.Duration.Round(time.Millisecond))
	fmt.Fprintf(w, "Findings  : %d total\n", len(result.Findings))

	bySev := make(map[models.Severity]int)
	for _, f := range result.Findings {
		bySev[f.Severity]++
	}

	for _, sev := range []models.Severity{
		models.SeverityCritical, models.SeverityHigh,
		models.SeverityMedium, models.SeverityLow, models.SeverityInfo,
	} {
		n := bySev[sev]
		if n == 0 {
			continue
		}
		severityColor(sev).Fprintf(w, "  %-10s: %d\n", sev, n)
	}
	colorBold.Fprintf(w, "%s\n", strings.Repeat("─", 60))
}

func PrintStaticSummary(w io.Writer, result *models.StaticAnalysisResult) {
	colorBold.Fprintf(w, "\n%s\n", strings.Repeat("─", 60))
	colorBold.Fprintf(w, "STATIC ANALYSIS SUMMARY\n")
	colorDim.Fprintf(w, "%s\n", strings.Repeat("─", 60))
	fmt.Fprintf(w, "Project   : %s (%s)\n", result.ProjectPath, result.ProjectType)
	fmt.Fprintf(w, "Duration  : %s\n", result.EndTime.Sub(result.StartTime).Round(time.Millisecond))
	fmt.Fprintf(w, "Deps scanned : %d (%d vulnerable)\n", result.Stats.DepsChecked, result.Stats.VulnerableDeps)
	fmt.Fprintf(w, "Findings  : %d total\n", len(result.Findings))

	// Sort by severity
	sorted := make([]*models.Finding, len(result.Findings))
	copy(sorted, result.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].SeverityScore() > sorted[j].SeverityScore()
	})
	for _, f := range sorted {
		PrintFinding(w, f)
	}
	colorBold.Fprintf(w, "\n%s\n", strings.Repeat("─", 60))
}

func severityColor(s models.Severity) *color.Color {
	switch s {
	case models.SeverityCritical:
		return colorCritical
	case models.SeverityHigh:
		return colorHigh
	case models.SeverityMedium:
		return colorMedium
	case models.SeverityLow:
		return colorLow
	default:
		return colorInfo
	}
}

func confidenceOrZero(fp *models.FingerprintData) int {
	if fp == nil {
		return 0
	}
	return fp.Confidence
}
