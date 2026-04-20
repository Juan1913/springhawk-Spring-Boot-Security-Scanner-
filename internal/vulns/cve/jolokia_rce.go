package cve

// Jolokia RCE via JNDI or reloadByURL / createJNDIRealm gadgets
// Jolokia exposes JMX beans over HTTP — certain beans allow code execution

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

func init() { vulns.RegisterRemote(&JolokiaRCE{}) }

type JolokiaRCE struct{}

func (m *JolokiaRCE) ID() string          { return "jolokia-rce" }
func (m *JolokiaRCE) Name() string        { return "Jolokia JMX RCE" }
func (m *JolokiaRCE) CVSS() float64       { return 8.1 }
func (m *JolokiaRCE) Severity() models.Severity { return models.SeverityHigh }
func (m *JolokiaRCE) Tags() []string      { return []string{"rce", "jolokia", "jmx", "actuator", "jndi"} }
func (m *JolokiaRCE) Requirements() vulns.ModuleRequirements { return vulns.ModuleRequirements{} }
func (m *JolokiaRCE) Description() string {
	return "Jolokia exposes JMX beans over HTTP. The reloadByURL or createJNDIRealm operations allow JNDI-based RCE."
}

func (m *JolokiaRCE) Check(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	jolokiaPaths := []string{"jolokia", "actuator/jolokia"}

	for _, p := range jolokiaPaths {
		// Check base Jolokia endpoint
		resp, err := client.Post(ctx, utils.JoinURL(target.BaseURL, p),
			"application/x-www-form-urlencoded", strings.NewReader(""), nil)
		if err != nil || resp.StatusCode != 200 {
			continue
		}

		// Check /list for dangerous operations
		listResp, err := client.Get(ctx, utils.JoinURL(target.BaseURL, p+"/list"), nil)
		if err != nil || listResp.StatusCode != 200 {
			continue
		}

		var evidence string
		if strings.Contains(listResp.BodyString, "reloadByURL") {
			evidence = "Dangerous operation 'reloadByURL' found in Jolokia MBean list — log4j JNDI RCE vector available."
		} else if strings.Contains(listResp.BodyString, "createJNDIRealm") {
			evidence = "Dangerous operation 'createJNDIRealm' found — Tomcat JNDI RCE via Jolokia possible."
		} else {
			evidence = fmt.Sprintf("Jolokia endpoint exposed at /%s. %d MBeans accessible.", p, strings.Count(listResp.BodyString, `"op"`))
		}

		f := &models.Finding{
			ID:          fmt.Sprintf("%s-%d", m.ID(), time.Now().UnixNano()),
			Type:        models.FindingTypeVuln,
			Severity:    m.Severity(),
			CVSS:        m.CVSS(),
			Title:       "Jolokia JMX Endpoint Exposed with Dangerous Operations",
			Description: m.Description(),
			URL:         target.BaseURL,
			Endpoint:    "/" + p,
			Method:      "GET",
			Evidence:    evidence,
			Remediation: "Disable Jolokia or restrict to localhost. Remove jolokia from exposed actuator endpoints. Upgrade to Jolokia 1.7.1+.",
			References:  []string{"https://jolokia.org/reference/html/security.html", "https://github.com/LandGrey/SpringBootVulExploit#0x05jolokia-realm-jndi-rce"},
			Tags:        m.Tags(),
			Timestamp:   time.Now(),
			ModuleID:    m.ID(),
		}
		return []*models.Finding{f}, nil
	}
	return nil, nil
}

func (m *JolokiaRCE) Exploit(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	return m.Check(ctx, target, client)
}
