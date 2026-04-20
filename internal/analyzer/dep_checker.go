package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/springhawk/springhawk/internal/vulns"
	"github.com/springhawk/springhawk/pkg/models"
	"github.com/springhawk/springhawk/pkg/utils"
)

func init() { vulns.RegisterStatic(&DepChecker{}) }

type DepChecker struct {
	DB VulnDB
}

type VulnDB map[string][]VulnEntry

type VulnEntry struct {
	CVE      string   `json:"cve"`
	Affected []string `json:"affected"`
	Fixed    string   `json:"fixed"`
	Severity string   `json:"severity"`
	CVSS     float64  `json:"cvss"`
	Desc     string   `json:"description"`
}

func NewDepChecker(dbJSON []byte) (*DepChecker, error) {
	var db VulnDB
	if err := json.Unmarshal(dbJSON, &db); err != nil {
		return nil, err
	}
	return &DepChecker{DB: db}, nil
}

func (m *DepChecker) ID() string              { return "dep-checker" }
func (m *DepChecker) Name() string            { return "Vulnerable Dependency Version Checker" }
func (m *DepChecker) Category() vulns.StaticCategory { return vulns.StaticDependency }

func (m *DepChecker) Check(ctx context.Context, proj *vulns.ProjectContext) ([]*models.Finding, error) {
	var findings []*models.Finding
	allDeps := append(proj.PomDeps, proj.GradleDeps...)

	for _, dep := range allDeps {
		if dep.Version == "" || dep.IsVulnerable {
			continue
		}
		entries, ok := m.DB[dep.ArtifactID]
		if !ok {
			continue
		}
		for _, entry := range entries {
			for _, affected := range entry.Affected {
				if utils.InRange(dep.Version, affected) {
					dep.IsVulnerable = true
					dep.CVEs = append(dep.CVEs, entry.CVE)

					f := &models.Finding{
						ID:          fmt.Sprintf("dep-%s-%s-%d", dep.ArtifactID, entry.CVE, time.Now().UnixNano()),
						Type:        models.FindingTypeVuln,
						Severity:    models.Severity(entry.Severity),
						CVSS:        entry.CVSS,
						CVEIDs:      []string{entry.CVE},
						Title:       fmt.Sprintf("Vulnerable Dependency: %s:%s@%s (%s)", dep.GroupID, dep.ArtifactID, dep.Version, entry.CVE),
						Description: entry.Desc,
						URL:         proj.ProjectPath,
						Evidence:    fmt.Sprintf("Version %s is in vulnerable range %s. Fixed in: %s", dep.Version, affected, entry.Fixed),
						Remediation: fmt.Sprintf("Upgrade %s to %s or higher.", dep.ArtifactID, entry.Fixed),
						References:  []string{fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", entry.CVE)},
						Tags:        []string{"dependency", "sca", dep.ArtifactID},
						Timestamp:   time.Now(),
						ModuleID:    m.ID(),
					}
					findings = append(findings, f)
					break
				}
			}
		}
	}
	return findings, nil
}
