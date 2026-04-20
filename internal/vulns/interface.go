package vulns

import (
	"context"

	httpclient "github.com/springhawk/springhawk/internal/http"
	"github.com/springhawk/springhawk/pkg/models"
)

// VulnModule is the core interface every remote vulnerability module must implement.
// Check = safe detection only. Exploit = active exploitation (requires --exploit flag).
type VulnModule interface {
	ID() string
	Name() string
	Description() string
	Severity() models.Severity
	CVSS() float64
	Tags() []string
	Requirements() ModuleRequirements
	Check(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error)
	Exploit(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error)
}

type ModuleRequirements struct {
	RequiresSpringCloud bool
	RequiresCallback    bool
	MinConfidence       int
}

// StaticModule is the interface for local static analysis checks.
type StaticModule interface {
	ID() string
	Name() string
	Category() StaticCategory
	Check(ctx context.Context, proj *ProjectContext) ([]*models.Finding, error)
}

type StaticCategory string

const (
	StaticDependency StaticCategory = "dependency"
	StaticConfig     StaticCategory = "config"
	StaticSecret     StaticCategory = "secret"
	StaticCode       StaticCategory = "code"
)

type ProjectContext struct {
	ProjectPath string
	ProjectType string // "maven" | "gradle" | "unknown"
	PomDeps     []models.DependencyInfo
	GradleDeps  []models.DependencyInfo
	Properties  map[string]string
	SourceFiles []SourceFile
	ConfigFiles []ConfigFile
}

type SourceFile struct {
	Path    string
	Content string
	Lang    string // "java" | "kotlin"
}

type ConfigFile struct {
	Path    string
	Content string
	Type    string // "properties" | "yaml"
}
