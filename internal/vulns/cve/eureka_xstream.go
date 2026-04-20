package cve

// Eureka XStream deserialization RCE
// Sets eureka.client.serviceUrl.defaultZone to a malicious XML URL via /actuator/env
// XStream deserializes the response triggering RCE

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

func init() { vulns.RegisterRemote(&EurekaXStream{}) }

type EurekaXStream struct{}

func (m *EurekaXStream) ID() string          { return "eureka-xstream-rce" }
func (m *EurekaXStream) Name() string        { return "Eureka XStream Deserialization RCE" }
func (m *EurekaXStream) CVSS() float64       { return 9.8 }
func (m *EurekaXStream) Severity() models.Severity { return models.SeverityCritical }
func (m *EurekaXStream) Tags() []string      { return []string{"rce", "deserialization", "xstream", "eureka", "actuator"} }
func (m *EurekaXStream) Requirements() vulns.ModuleRequirements { return vulns.ModuleRequirements{} }
func (m *EurekaXStream) Description() string {
	return "Eureka client deserializes XML from the configured serviceUrl using XStream, enabling RCE when the property is writable via /actuator/env."
}

func (m *EurekaXStream) Check(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	envPaths := []struct{ env string; v2 bool }{
		{"actuator/env", true},
		{"env", false},
	}

	for _, p := range envPaths {
		envURL := utils.JoinURL(target.BaseURL, p.env)

		// First check if eureka property is present
		getResp, err := client.Get(ctx, envURL, nil)
		if err != nil || getResp.StatusCode != 200 {
			continue
		}
		if !strings.Contains(getResp.BodyString, "eureka") {
			continue
		}

		// Try to write a canary eureka URL
		var body, ct string
		if p.v2 {
			body = `{"name":"eureka.client.serviceUrl.defaultZone","value":"http://springhawk-check.invalid/eureka"}`
			ct = "application/json"
		} else {
			body = "eureka.client.serviceUrl.defaultZone=http://springhawk-check.invalid/eureka"
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
			Title:       "Eureka XStream Deserialization RCE via Actuator /env",
			Description: m.Description(),
			URL:         target.BaseURL,
			Endpoint:    "/" + p.env,
			Method:      "POST",
			Evidence:    fmt.Sprintf("Eureka property found in /%s and property write accepted (HTTP %d).", p.env, resp.StatusCode),
			Remediation: "Restrict /actuator/env write access. Upgrade XStream to 1.4.19+. Use allowlist deserialization.",
			References:  []string{"https://github.com/LandGrey/SpringBootVulExploit"},
			Tags:        m.Tags(),
			Timestamp:   time.Now(),
			ModuleID:    m.ID(),
		}
		return []*models.Finding{f}, nil
	}
	return nil, nil
}

func (m *EurekaXStream) Exploit(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	return m.Check(ctx, target, client)
}
