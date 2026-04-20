package analyzer

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/springhawk/springhawk/internal/vulns"
)

// Detect walks projectRoot to discover build system, config files, and source files.
func Detect(projectRoot string) (*vulns.ProjectContext, error) {
	ctx := &vulns.ProjectContext{
		ProjectPath: projectRoot,
		ProjectType: "unknown",
		Properties:  make(map[string]string),
	}

	// Detect build system
	if fileExists(filepath.Join(projectRoot, "pom.xml")) {
		ctx.ProjectType = "maven"
	} else if fileExists(filepath.Join(projectRoot, "build.gradle")) ||
		fileExists(filepath.Join(projectRoot, "build.gradle.kts")) {
		ctx.ProjectType = "gradle"
	}

	// Walk directory tree
	err := filepath.WalkDir(projectRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			// Skip common noise dirs
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "target" || name == "build" || name == ".gradle" {
				return filepath.SkipDir
			}
			return nil
		}

		name := d.Name()
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		text := string(content)

		switch {
		case name == "pom.xml" && ctx.ProjectType == "maven":
			deps, _ := ParsePOM(text)
			ctx.PomDeps = append(ctx.PomDeps, deps...)

		case name == "build.gradle" || name == "build.gradle.kts":
			deps := ParseGradle(text)
			ctx.GradleDeps = append(ctx.GradleDeps, deps...)

		case name == "application.properties":
			props := ParseProperties(text)
			for k, v := range props {
				ctx.Properties[k] = v
			}
			ctx.ConfigFiles = append(ctx.ConfigFiles, vulns.ConfigFile{
				Path: path, Content: text, Type: "properties",
			})

		case name == "application.yml" || name == "application.yaml":
			props := ParseYAMLFlat(text)
			for k, v := range props {
				ctx.Properties[k] = v
			}
			ctx.ConfigFiles = append(ctx.ConfigFiles, vulns.ConfigFile{
				Path: path, Content: text, Type: "yaml",
			})

		case strings.HasSuffix(name, ".java"):
			ctx.SourceFiles = append(ctx.SourceFiles, vulns.SourceFile{
				Path: path, Content: text, Lang: "java",
			})

		case strings.HasSuffix(name, ".kt"):
			ctx.SourceFiles = append(ctx.SourceFiles, vulns.SourceFile{
				Path: path, Content: text, Lang: "kotlin",
			})
		}

		return nil
	})

	return ctx, err
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
