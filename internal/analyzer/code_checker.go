package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/springhawk/springhawk/internal/vulns"
	"github.com/springhawk/springhawk/pkg/models"
)

func init() { vulns.RegisterStatic(&CodeChecker{}) }

type CodeChecker struct{}

func (m *CodeChecker) ID() string              { return "code-checker" }
func (m *CodeChecker) Name() string            { return "Insecure Code Pattern Scanner" }
func (m *CodeChecker) Category() vulns.StaticCategory { return vulns.StaticCode }

type codeRule struct {
	name     string
	re       *regexp.Regexp
	message  string
	severity models.Severity
	fix      string
}

var codeRules = []codeRule{
	{
		name:     "CORS Wildcard @CrossOrigin",
		re:       regexp.MustCompile(`@CrossOrigin\s*\(\s*(?:origins\s*=\s*)?["']\*["']`),
		message:  "@CrossOrigin with wildcard origin allows any domain to make credentialed requests",
		severity: models.SeverityMedium,
		fix:      "Specify exact allowed origins: @CrossOrigin(origins = {\"https://yourdomain.com\"})",
	},
	{
		name:     "Missing @PreAuthorize on Controller",
		re:       regexp.MustCompile(`@(?:Rest)?Controller\b`),
		message:  "Controller class found without method-level security annotations — verify all endpoints are protected",
		severity: models.SeverityInfo,
		fix:      "Add @PreAuthorize(\"isAuthenticated()\") or role checks on sensitive endpoints",
	},
	{
		name:     "Runtime.exec() Call",
		re:       regexp.MustCompile(`Runtime\.getRuntime\(\)\.exec\(`),
		message:  "Dangerous Runtime.exec() call — may be exploitable for OS command injection if user input reaches here",
		severity: models.SeverityHigh,
		fix:      "Validate and sanitize all inputs. Prefer ProcessBuilder with an allowlist of commands.",
	},
	{
		name:     "ProcessBuilder with String Concat",
		re:       regexp.MustCompile(`new ProcessBuilder\([^)]*\+[^)]*\)`),
		message:  "ProcessBuilder constructed with string concatenation — potential command injection",
		severity: models.SeverityHigh,
		fix:      "Use a List<String> with fixed arguments. Never concatenate user input into command strings.",
	},
	{
		name:     "SQL with String Concatenation",
		re:       regexp.MustCompile(`(?i)(createQuery|createNativeQuery|executeQuery|prepareStatement)\s*\([^)]*\+[^)]*\)`),
		message:  "SQL query built with string concatenation — SQL injection risk",
		severity: models.SeverityCritical,
		fix:      "Use parameterized queries: createQuery(\"SELECT * FROM users WHERE id = :id\").setParameter(\"id\", id)",
	},
	{
		name:     "ObjectInputStream Deserialization",
		re:       regexp.MustCompile(`new ObjectInputStream\(`),
		message:  "ObjectInputStream used — Java deserialization may be exploitable if data comes from untrusted sources",
		severity: models.SeverityHigh,
		fix:      "Avoid Java serialization. Use JSON/XML with explicit type mapping. Implement resolveClass() filtering.",
	},
	{
		name:     "XSS via PrintWriter/ResponseWriter",
		re:       regexp.MustCompile(`response\.getWriter\(\)\.(?:print|write|println)\([^)]*(?:getParameter|request\.)[^)]*\)`),
		message:  "User input written directly to HTTP response without encoding — XSS vulnerability",
		severity: models.SeverityHigh,
		fix:      "Use HTML encoding: StringEscapeUtils.escapeHtml4() or Thymeleaf/JSP expression syntax.",
	},
	{
		name:     "Permissive File Upload",
		re:       regexp.MustCompile(`(?i)MultipartFile.*getOriginalFilename\(\)`),
		message:  "MultipartFile.getOriginalFilename() used — filename from client is untrusted",
		severity: models.SeverityMedium,
		fix:      "Generate server-side filename. Validate file type by content (not extension). Store outside web root.",
	},
	{
		name:     "Path Traversal Risk",
		re:       regexp.MustCompile(`new File\s*\([^)]*(?:getParameter|request\.|param)[^)]*\)`),
		message:  "File object constructed from request parameter — path traversal risk",
		severity: models.SeverityHigh,
		fix:      "Validate and canonicalize paths. Ensure resolved path is within allowed directory.",
	},
	{
		name:     "Disabled CSRF Protection",
		re:       regexp.MustCompile(`\.csrf\(\)\s*\.disable\(\)`),
		message:  "CSRF protection explicitly disabled in Spring Security configuration",
		severity: models.SeverityHigh,
		fix:      "Enable CSRF protection. Only disable for stateless REST APIs using JWT/token auth.",
	},
	{
		name:     "permitAll on All Requests",
		re:       regexp.MustCompile(`anyRequest\(\)\s*\.permitAll\(\)`),
		message:  "Spring Security configured to allow ALL requests without authentication",
		severity: models.SeverityCritical,
		fix:      "Replace with .authenticated() or specific role checks. Apply deny-by-default.",
	},
}

func (m *CodeChecker) Check(ctx context.Context, proj *vulns.ProjectContext) ([]*models.Finding, error) {
	var findings []*models.Finding

	for _, sf := range proj.SourceFiles {
		lines := strings.Split(sf.Content, "\n")
		for lineNum, line := range lines {
			for _, rule := range codeRules {
				if !rule.re.MatchString(line) {
					continue
				}
				f := &models.Finding{
					ID:          fmt.Sprintf("code-%s-L%d-%d", sanitizeKey(rule.name), lineNum+1, time.Now().UnixNano()),
					Type:        models.FindingTypeConfig,
					Severity:    rule.severity,
					Title:       fmt.Sprintf("Insecure Code Pattern: %s", rule.name),
					Description: rule.message,
					URL:         sf.Path,
					Endpoint:    fmt.Sprintf("Line %d", lineNum+1),
					Evidence:    fmt.Sprintf("%s:%d: %s", sf.Path, lineNum+1, strings.TrimSpace(line)),
					Remediation: rule.fix,
					Tags:        []string{"code-review", "sast", sf.Lang},
					Timestamp:   time.Now(),
					ModuleID:    m.ID(),
				}
				findings = append(findings, f)
				break // one rule match per line
			}
		}
	}
	return findings, nil
}
