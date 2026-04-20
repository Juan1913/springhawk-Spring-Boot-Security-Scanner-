package analyzer

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseYAMLFlat parses application.yml and returns a flat dotted-key map
// e.g. spring.datasource.password -> value
func ParseYAMLFlat(content string) map[string]string {
	result := make(map[string]string)
	var raw map[string]interface{}
	if err := yaml.Unmarshal([]byte(content), &raw); err != nil {
		return result
	}
	flattenMap("", raw, result)
	return result
}

func flattenMap(prefix string, m map[string]interface{}, out map[string]string) {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch val := v.(type) {
		case map[string]interface{}:
			flattenMap(key, val, out)
		case map[interface{}]interface{}:
			typed := make(map[string]interface{})
			for mk, mv := range val {
				typed[fmt.Sprintf("%v", mk)] = mv
			}
			flattenMap(key, typed, out)
		default:
			if val != nil {
				out[key] = fmt.Sprintf("%v", val)
			} else {
				out[key] = ""
			}
		}
	}
}

// FlattenYAMLList converts a slice of yaml values to comma-joined string
func FlattenYAMLList(v []interface{}) string {
	var parts []string
	for _, item := range v {
		parts = append(parts, fmt.Sprintf("%v", item))
	}
	return strings.Join(parts, ",")
}
