package analyzer

import (
	"regexp"
	"strings"

	"github.com/springhawk/springhawk/pkg/models"
)

var gradleDepRe = regexp.MustCompile(`(?:implementation|compile|api|testImplementation|runtimeOnly)\s+['"]([^'"]+)['"]`)

// ParseGradle extracts dependencies from build.gradle or build.gradle.kts.
func ParseGradle(content string) []models.DependencyInfo {
	var deps []models.DependencyInfo
	matches := gradleDepRe.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		parts := strings.Split(m[1], ":")
		if len(parts) < 2 {
			continue
		}
		dep := models.DependencyInfo{
			GroupID:    parts[0],
			ArtifactID: parts[1],
		}
		if len(parts) >= 3 {
			dep.Version = parts[2]
		}
		deps = append(deps, dep)
	}
	return deps
}
