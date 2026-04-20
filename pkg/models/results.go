package models

import "time"

type ScanStats struct {
	TotalEndpoints     int
	CheckedEndpoints   int
	FoundEndpoints     int
	TotalModules       int
	ExecutedModules    int
	FindingsBySeverity map[Severity]int
	RequestsMade       int
	BytesTransferred   int64
}

type ScanError struct {
	ModuleID  string
	Endpoint  string
	Error     string
	Timestamp time.Time
}

type ScanResult struct {
	ScanID       string
	Target       *Target
	StartTime    time.Time
	EndTime      time.Time
	Duration     time.Duration
	IsSpringBoot bool
	Fingerprint  *FingerprintData
	Findings     []*Finding
	Stats        ScanStats
	Errors       []ScanError
}

type DependencyInfo struct {
	GroupID      string
	ArtifactID   string
	Version      string
	Scope        string
	CVEs         []string
	IsVulnerable bool
}

type AnalysisStats struct {
	FilesScanned       int
	DepsChecked        int
	VulnerableDeps     int
	SecretsFound       int
	ConfigIssues       int
	CodeIssues         int
	FindingsBySeverity map[Severity]int
}

type StaticAnalysisResult struct {
	AnalysisID   string
	ProjectPath  string
	ProjectType  string
	StartTime    time.Time
	EndTime      time.Time
	Findings     []*Finding
	Dependencies []DependencyInfo
	Stats        AnalysisStats
}
