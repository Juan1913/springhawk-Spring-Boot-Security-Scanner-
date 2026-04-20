package web

// Swagger/OpenAPI endpoint enumeration
// Discovers exposed API documentation that reveals endpoint structure

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

func init() { vulns.RegisterRemote(&SwaggerEnum{}) }

type SwaggerEnum struct{}

func (m *SwaggerEnum) ID() string               { return "swagger-exposure" }
func (m *SwaggerEnum) Name() string             { return "Swagger/OpenAPI Docs Exposed" }
func (m *SwaggerEnum) CVSS() float64            { return 5.3 }
func (m *SwaggerEnum) Severity() models.Severity { return models.SeverityMedium }
func (m *SwaggerEnum) Tags() []string { return []string{"info-disclosure", "swagger", "openapi", "api-docs"} }
func (m *SwaggerEnum) Requirements() vulns.ModuleRequirements { return vulns.ModuleRequirements{} }
func (m *SwaggerEnum) Description() string {
	return "Swagger/OpenAPI documentation is publicly accessible, revealing all API endpoints, parameters, and authentication requirements."
}

var swaggerPaths = []struct {
	path   string
	needle string
}{
	{"swagger-ui.html", "swagger"},
	{"swagger-ui/index.html", "swagger"},
	{"swagger-ui/", "swagger"},
	{"v2/api-docs", `"swagger"`},
	{"v3/api-docs", `"openapi"`},
	{"v3/api-docs/swagger-config", "url"},
	{"api-docs", `"paths"`},
	{"api/swagger-ui.html", "swagger"},
	{"api/v2/api-docs", `"swagger"`},
	{"api/v3/api-docs", `"openapi"`},
	{"swagger.json", `"swagger"`},
	{"swagger.yaml", "swagger:"},
	{"api-docs.json", `"paths"`},
}

func (m *SwaggerEnum) Check(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	var findings []*models.Finding

	for _, s := range swaggerPaths {
		resp, err := client.Get(ctx, utils.JoinURL(target.BaseURL, s.path), nil)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		if !strings.Contains(strings.ToLower(resp.BodyString), strings.ToLower(s.needle)) {
			continue
		}

		// Count endpoints if it's an API doc
		endpointCount := strings.Count(resp.BodyString, `"path"`) + strings.Count(resp.BodyString, `"get"`) + strings.Count(resp.BodyString, `"post"`)

		f := &models.Finding{
			ID:          fmt.Sprintf("%s-%s-%d", m.ID(), s.path, time.Now().UnixNano()),
			Type:        models.FindingTypeExpose,
			Severity:    m.Severity(),
			CVSS:        m.CVSS(),
			Title:       fmt.Sprintf("API Documentation Exposed: /%s", s.path),
			Description: m.Description(),
			URL:         target.BaseURL,
			Endpoint:    "/" + s.path,
			Method:      "GET",
			Evidence:    fmt.Sprintf("API docs accessible at /%s (~%d endpoint references found).", s.path, endpointCount),
			Remediation: "Disable Swagger UI in production: springfox.documentation.enabled=false or springdoc.api-docs.enabled=false.",
			Tags:        m.Tags(),
			Timestamp:   time.Now(),
			ModuleID:    m.ID(),
		}
		findings = append(findings, f)
		break // one finding per target is enough
	}
	return findings, nil
}

func (m *SwaggerEnum) Exploit(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	return m.Check(ctx, target, client)
}
