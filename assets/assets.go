package assets

import (
	"bufio"
	"embed"
	"strings"
)

//go:embed wordlists/* signatures/*
var FS embed.FS

// Endpoints returns a deduplicated list of endpoints from all wordlist files.
func Endpoints() ([]string, error) {
	data, err := FS.ReadFile("wordlists/endpoints_core.txt")
	if err != nil {
		return nil, err
	}
	var out []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !seen[line] {
			seen[line] = true
			out = append(out, line)
		}
	}
	return out, nil
}

// VulnVersionDB returns the raw JSON bytes of the vulnerability version database.
func VulnVersionDB() ([]byte, error) {
	return FS.ReadFile("signatures/vuln_versions.json")
}

// FaviconHashes returns the raw JSON bytes of the favicon hash database.
func FaviconHashes() ([]byte, error) {
	return FS.ReadFile("signatures/favicon_hashes.json")
}
