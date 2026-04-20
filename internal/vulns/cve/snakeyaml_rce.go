package cve

// SnakeYAML RCE via Spring Boot Actuator /env endpoint
// Sets spring.cloud.bootstrap.location to a malicious YAML URL
// Triggers deserialization when /refresh is called

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

func init() { vulns.RegisterRemote(&SnakeYAMLRCE{}) }

type SnakeYAMLRCE struct{}

func (m *SnakeYAMLRCE) ID() string          { return "snakeyaml-rce" }
func (m *SnakeYAMLRCE) Name() string        { return "SnakeYAML Deserialization RCE" }
func (m *SnakeYAMLRCE) CVSS() float64       { return 9.8 }
func (m *SnakeYAMLRCE) Severity() models.Severity { return models.SeverityCritical }
func (m *SnakeYAMLRCE) Tags() []string      { return []string{"rce", "deserialization", "snakeyaml", "actuator", "env"} }
func (m *SnakeYAMLRCE) Requirements() vulns.ModuleRequirements { return vulns.ModuleRequirements{} }
func (m *SnakeYAMLRCE) Description() string {
	return "Spring Boot Actuator /env allows setting spring.cloud.bootstrap.location to a remote YAML, triggering SnakeYAML deserialization RCE on /refresh."
}

func (m *SnakeYAMLRCE) Check(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	// Check if /actuator/env or /env is writable
	envPaths := []struct {
		env, refresh string
		v2           bool
	}{
		{"actuator/env", "actuator/refresh", true},
		{"env", "refresh", false},
	}

	for _, p := range envPaths {
		envURL := utils.JoinURL(target.BaseURL, p.env)

		var body, ct string
		if p.v2 {
			body = `{"name":"spring.cloud.bootstrap.location","value":"http://springhawk-check.invalid/test.yml"}`
			ct = "application/json"
		} else {
			body = "spring.cloud.bootstrap.location=http://springhawk-check.invalid/test.yml"
			ct = "application/x-www-form-urlencoded"
		}

		resp, err := client.Post(ctx, envURL, ct, strings.NewReader(body), nil)
		if err != nil || (resp.StatusCode != 200 && resp.StatusCode != 204) {
			continue
		}
		// Verify the property was accepted
		if !strings.Contains(resp.BodyString, "bootstrap.location") && resp.StatusCode != 204 {
			continue
		}

		f := &models.Finding{
			ID:          fmt.Sprintf("%s-%d", m.ID(), time.Now().UnixNano()),
			Type:        models.FindingTypeVuln,
			Severity:    m.Severity(),
			CVSS:        m.CVSS(),
			Title:       "SnakeYAML Deserialization RCE via Spring Actuator /env",
			Description: m.Description(),
			URL:         target.BaseURL,
			Endpoint:    "/" + p.env,
			Method:      "POST",
			Evidence:    fmt.Sprintf("/%s accepted property write (HTTP %d). Triggering /refresh with malicious YAML URL would execute code.", p.env, resp.StatusCode),
			Remediation: "Restrict access to /actuator/env and /actuator/refresh. Upgrade SnakeYAML to 1.31+. Use SafeConstructor.",
			References:  []string{"https://github.com/artsploit/yaml-payload"},
			Tags:        m.Tags(),
			Timestamp:   time.Now(),
			ModuleID:    m.ID(),
		}
		return []*models.Finding{f}, nil
	}
	return nil, nil
}

func (m *SnakeYAMLRCE) Exploit(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	return m.Check(ctx, target, client)
}
