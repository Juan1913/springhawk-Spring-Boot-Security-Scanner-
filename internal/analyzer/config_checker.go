package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/springhawk/springhawk/internal/vulns"
	"github.com/springhawk/springhawk/pkg/models"
)

func init() { vulns.RegisterStatic(&ConfigChecker{}) }

type ConfigChecker struct{}

func (m *ConfigChecker) ID() string              { return "config-checker" }
func (m *ConfigChecker) Name() string            { return "Spring Boot Configuration Auditor" }
func (m *ConfigChecker) Category() vulns.StaticCategory { return vulns.StaticConfig }

type configRule struct {
	key      string
	badValue string // empty = any value is bad
	message  string
	severity models.Severity
	fix      string
}

var configRules = []configRule{
	{
		key:      "management.endpoints.web.exposure.include",
		badValue: "*",
		message:  "All actuator endpoints exposed — heapdump, env, configprops, etc. accessible",
		severity: models.SeverityCritical,
		fix:      "Set to only required endpoints, e.g.: management.endpoints.web.exposure.include=health,info",
	},
	{
		key:      "spring.h2.console.enabled",
		badValue: "true",
		message:  "H2 web console enabled — allows SQL execution and potential RCE",
		severity: models.SeverityCritical,
		fix:      "Set spring.h2.console.enabled=false in production",
	},
	{
		key:      "debug",
		badValue: "true",
		message:  "Spring Boot debug mode enabled — verbose error pages and classpath exposure",
		severity: models.SeverityMedium,
		fix:      "Set debug=false or remove the property",
	},
	{
		key:      "server.ssl.enabled",
		badValue: "false",
		message:  "SSL/TLS disabled — traffic transmitted in plaintext",
		severity: models.SeverityHigh,
		fix:      "Enable SSL: server.ssl.enabled=true with a valid keystore",
	},
	{
		key:      "security.basic.enabled",
		badValue: "false",
		message:  "Spring Security basic auth disabled globally",
		severity: models.SeverityHigh,
		fix:      "Remove this property or use proper WebSecurityConfigurerAdapter",
	},
	{
		key:      "management.security.enabled",
		badValue: "false",
		message:  "Actuator endpoint security disabled — all management endpoints publicly accessible",
		severity: models.SeverityCritical,
		fix:      "Set management.security.enabled=true",
	},
	{
		key:      "spring.jpa.show-sql",
		badValue: "true",
		message:  "SQL queries logged — may expose sensitive data in logs",
		severity: models.SeverityLow,
		fix:      "Set spring.jpa.show-sql=false in production",
	},
	{
		key:      "logging.level.root",
		badValue: "DEBUG",
		message:  "Root log level set to DEBUG — verbose output may expose internal state",
		severity: models.SeverityLow,
		fix:      "Set logging.level.root=INFO or WARN in production",
	},
	{
		key:      "spring.devtools.remote.secret",
		badValue: "",
		message:  "Spring DevTools remote secret configured — DevTools may be enabled in production",
		severity: models.SeverityHigh,
		fix:      "Remove spring-boot-devtools dependency from production builds",
	},
}

func (m *ConfigChecker) Check(ctx context.Context, proj *vulns.ProjectContext) ([]*models.Finding, error) {
	var findings []*models.Finding

	for _, rule := range configRules {
		val, ok := proj.Properties[rule.key]
		if !ok {
			continue
		}
		// Check: if badValue is empty, any value triggers; else must match
		if rule.badValue != "" && !strings.EqualFold(val, rule.badValue) {
			continue
		}

		configFile := "application configuration"
		for _, cf := range proj.ConfigFiles {
			if hasKey(cf.Content, rule.key) {
				configFile = cf.Path
				break
			}
		}

		f := &models.Finding{
			ID:          fmt.Sprintf("config-%s-%d", sanitizeKey(rule.key), time.Now().UnixNano()),
			Type:        models.FindingTypeConfig,
			Severity:    rule.severity,
			Title:       fmt.Sprintf("Dangerous Configuration: %s=%s", rule.key, val),
			Description: rule.message,
			URL:         proj.ProjectPath,
			Evidence:    fmt.Sprintf("Found in %s: %s=%s", configFile, rule.key, val),
			Remediation: rule.fix,
			Tags:        []string{"configuration", "spring-boot"},
			Timestamp:   time.Now(),
			ModuleID:    m.ID(),
		}
		findings = append(findings, f)
	}

	// Special check: CORS wildcard in properties
	if v, ok := proj.Properties["cors.allowed-origins"]; ok && v == "*" {
		findings = append(findings, corsWildcardFinding(proj))
	}

	return findings, nil
}

func corsWildcardFinding(proj *vulns.ProjectContext) *models.Finding {
	return &models.Finding{
		ID:          fmt.Sprintf("config-cors-%d", time.Now().UnixNano()),
		Type:        models.FindingTypeConfig,
		Severity:    models.SeverityMedium,
		Title:       "CORS Wildcard Configured: cors.allowed-origins=*",
		Description: "Cross-Origin Resource Sharing allows any origin — enables CSRF in browser contexts.",
		URL:         proj.ProjectPath,
		Evidence:    "cors.allowed-origins=* in application configuration",
		Remediation: "Restrict allowed origins to known domains. Do not use * with credentials.",
		Tags:        []string{"cors", "configuration"},
		Timestamp:   time.Now(),
		ModuleID:    "config-checker",
	}
}

func hasKey(content, key string) bool {
	return strings.Contains(content, key)
}

func sanitizeKey(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, ".", "-"), "_", "-")
}
