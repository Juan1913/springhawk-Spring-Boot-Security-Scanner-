package models

import "time"

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

type FindingType string

const (
	FindingTypeVuln   FindingType = "VULNERABILITY"
	FindingTypeExpose FindingType = "EXPOSURE"
	FindingTypeConfig FindingType = "MISCONFIGURATION"
	FindingTypeSecret FindingType = "SECRET"
	FindingTypeInfo   FindingType = "INFORMATION"
)

type HTTPEvidence struct {
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	StatusCode int               `json:"status_code"`
}

type Finding struct {
	ID          string            `json:"id"`
	Type        FindingType       `json:"type"`
	Severity    Severity          `json:"severity"`
	CVSS        float64           `json:"cvss"`
	CVEIDs      []string          `json:"cve_ids,omitempty"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	URL         string            `json:"url"`
	Endpoint    string            `json:"endpoint"`
	Method      string            `json:"method,omitempty"`
	Request     *HTTPEvidence     `json:"request,omitempty"`
	Response    *HTTPEvidence     `json:"response,omitempty"`
	Evidence    string            `json:"evidence"`
	Payload     string            `json:"payload,omitempty"`
	Remediation string            `json:"remediation"`
	References  []string          `json:"references,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
	ModuleID    string            `json:"module_id"`
	IsExploited bool              `json:"is_exploited"`
	ExtraData   map[string]string `json:"extra_data,omitempty"`
}

func (f *Finding) SeverityScore() int {
	switch f.Severity {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	default:
		return 1
	}
}
