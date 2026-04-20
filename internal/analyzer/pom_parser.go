package analyzer

import (
	"encoding/xml"
	"strings"

	"github.com/springhawk/springhawk/pkg/models"
)

type pomXML struct {
	XMLName xml.Name `xml:"project"`
	Parent  struct {
		ArtifactID string `xml:"artifactId"`
		GroupID    string `xml:"groupId"`
		Version    string `xml:"version"`
	} `xml:"parent"`
	Properties  pomProperties `xml:"properties"`
	Deps        []pomDep      `xml:"dependencies>dependency"`
	DepMgmt     []pomDep      `xml:"dependencyManagement>dependencies>dependency"`
}

type pomProperties struct {
	Entries []xml.Token
	Map     map[string]string
}

type pomDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

// ParsePOM parses pom.xml and returns dependencies with resolved versions.
func ParsePOM(content string) ([]models.DependencyInfo, error) {
	var pom pomXML
	if err := xml.Unmarshal([]byte(content), &pom); err != nil {
		return nil, err
	}

	// Build property map from raw XML for ${property} interpolation
	props := extractProperties(content)

	// Add parent version as a known property
	if pom.Parent.Version != "" {
		props["project.parent.version"] = pom.Parent.Version
	}

	var deps []models.DependencyInfo
	for _, d := range append(pom.Deps, pom.DepMgmt...) {
		version := resolveProperty(d.Version, props)
		deps = append(deps, models.DependencyInfo{
			GroupID:    d.GroupID,
			ArtifactID: d.ArtifactID,
			Version:    version,
			Scope:      d.Scope,
		})
	}
	return deps, nil
}

// extractProperties uses simple regex-style parsing to get <properties> values.
func extractProperties(content string) map[string]string {
	props := make(map[string]string)
	// Find <properties>...</properties> block
	start := strings.Index(content, "<properties>")
	end := strings.Index(content, "</properties>")
	if start == -1 || end == -1 {
		return props
	}
	block := content[start+12 : end]
	lines := strings.Split(block, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "<") {
			continue
		}
		// Parse <tagName>value</tagName>
		tagEnd := strings.Index(line, ">")
		if tagEnd == -1 {
			continue
		}
		tagName := line[1:tagEnd]
		if strings.Contains(tagName, " ") || strings.HasPrefix(tagName, "/") {
			continue
		}
		closing := "</" + tagName + ">"
		valStart := tagEnd + 1
		valEnd := strings.Index(line, closing)
		if valEnd == -1 {
			continue
		}
		props[tagName] = line[valStart:valEnd]
	}
	return props
}

func resolveProperty(val string, props map[string]string) string {
	if !strings.Contains(val, "${") {
		return val
	}
	start := strings.Index(val, "${")
	end := strings.Index(val, "}")
	if start == -1 || end == -1 {
		return val
	}
	key := val[start+2 : end]
	if resolved, ok := props[key]; ok {
		return resolved
	}
	return val
}
