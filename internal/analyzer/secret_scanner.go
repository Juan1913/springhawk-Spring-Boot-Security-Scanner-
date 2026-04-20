package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/springhawk/springhawk/internal/vulns"
	"github.com/springhawk/springhawk/pkg/models"
)

func init() { vulns.RegisterStatic(&SecretScanner{}) }

type SecretScanner struct{}

func (m *SecretScanner) ID() string              { return "secret-scanner" }
func (m *SecretScanner) Name() string            { return "Hardcoded Secrets & Credentials Scanner" }
func (m *SecretScanner) Category() vulns.StaticCategory { return vulns.StaticSecret }

type secretPattern struct {
	name     string
	re       *regexp.Regexp
	severity models.Severity
}

var secretPatterns = []secretPattern{
	{
		name:     "AWS Access Key",
		re:       regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`),
		severity: models.SeverityCritical,
	},
	{
		name:     "Private Key",
		re:       regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		severity: models.SeverityCritical,
	},
	{
		name:     "Spring Datasource Password",
		re:       regexp.MustCompile(`(?i)(spring\.datasource\.password\s*[=:]\s*)([^\s#\n]{4,})`),
		severity: models.SeverityHigh,
	},
	{
		name:     "JWT Secret",
		re:       regexp.MustCompile(`(?i)(jwt\.(secret|signing-key|token-secret)\s*[=:]\s*)([^\s#\n]{8,})`),
		severity: models.SeverityCritical,
	},
	{
		name:     "Generic Password Property",
		re:       regexp.MustCompile(`(?i)(password\s*[=:]\s*)([^\s#\n${]{6,})`),
		severity: models.SeverityHigh,
	},
	{
		name:     "Generic API Key",
		re:       regexp.MustCompile(`(?i)(api[_-]?key\s*[=:]\s*)([^\s#\n]{8,})`),
		severity: models.SeverityHigh,
	},
	{
		name:     "Generic Secret",
		re:       regexp.MustCompile(`(?i)(secret\s*[=:]\s*)([^\s#\n${]{8,})`),
		severity: models.SeverityHigh,
	},
	{
		name:     "Spring Security Hardcoded User",
		re:       regexp.MustCompile(`(?i)(spring\.security\.user\.password\s*[=:]\s*)([^\s#\n]{4,})`),
		severity: models.SeverityHigh,
	},
	{
		name:     "Database Connection String with Credentials",
		re:       regexp.MustCompile(`(?i)(jdbc:[a-z]+://[^@\s]*:[^@\s]*@[^\s"']+)`),
		severity: models.SeverityCritical,
	},
	{
		name:     "Google API Key",
		re:       regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`),
		severity: models.SeverityHigh,
	},
	{
		name:     "Slack Token",
		re:       regexp.MustCompile(`xox[baprs]-[0-9A-Za-z]{10,48}`),
		severity: models.SeverityHigh,
	},
	{
		name:     "GitHub Token",
		re:       regexp.MustCompile(`(?i)(ghp_|gho_|ghu_|ghs_|ghr_)[0-9A-Za-z]{36}`),
		severity: models.SeverityCritical,
	},
}

// Placeholder values that are not real secrets
var falsePositiveValues = []string{
	"your-secret-here", "${", "changeit", "change-me", "placeholder",
	"example", "dummy", "test123", "todo", "fixme",
}

func (m *SecretScanner) Check(ctx context.Context, proj *vulns.ProjectContext) ([]*models.Finding, error) {
	var findings []*models.Finding

	// Scan config files
	for _, cf := range proj.ConfigFiles {
		ff := scanContent(cf.Path, cf.Content, m.ID())
		findings = append(findings, ff...)
	}

	// Scan source files
	for _, sf := range proj.SourceFiles {
		ff := scanContent(sf.Path, sf.Content, m.ID())
		findings = append(findings, ff...)
	}

	return findings, nil
}

func scanContent(filePath, content, moduleID string) []*models.Finding {
	var findings []*models.Finding
	lines := strings.Split(content, "\n")

	for _, pattern := range secretPatterns {
		for lineNum, line := range lines {
			matches := pattern.re.FindStringSubmatch(line)
			if len(matches) == 0 {
				continue
			}
			value := matches[len(matches)-1]
			if isFalsePositive(value) {
				continue
			}

			masked := maskSecret(value)
			f := &models.Finding{
				ID:          fmt.Sprintf("secret-%s-L%d-%d", sanitizeKey(pattern.name), lineNum+1, time.Now().UnixNano()),
				Type:        models.FindingTypeSecret,
				Severity:    pattern.severity,
				Title:       fmt.Sprintf("Hardcoded Secret: %s", pattern.name),
				Description: fmt.Sprintf("%s found hardcoded in source — should be externalized via environment variables or Vault.", pattern.name),
				URL:         filePath,
				Endpoint:    fmt.Sprintf("Line %d", lineNum+1),
				Evidence:    fmt.Sprintf("File: %s, Line %d: ...%s...", filePath, lineNum+1, masked),
				Remediation: "Move secrets to environment variables, Spring Cloud Config, or HashiCorp Vault. Never commit credentials to version control.",
				Tags:        []string{"secret", "credential", "hardcoded"},
				Timestamp:   time.Now(),
				ModuleID:    moduleID,
			}
			findings = append(findings, f)
		}
	}
	return findings
}

func isFalsePositive(val string) bool {
	lower := strings.ToLower(val)
	for _, fp := range falsePositiveValues {
		if strings.Contains(lower, fp) {
			return true
		}
	}
	return false
}

func maskSecret(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}
