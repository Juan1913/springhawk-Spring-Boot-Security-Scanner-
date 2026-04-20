package http

import (
	"fmt"
	"net/url"
	"strings"
)

type EncodingVariant struct {
	Name    string
	Encoded string
}

// EncodeVariants returns multiple encoded forms of a path for WAF evasion.
func EncodeVariants(path string) []EncodingVariant {
	variants := []EncodingVariant{
		{Name: "raw", Encoded: path},
		{Name: "url", Encoded: url.PathEscape(path)},
		{Name: "double-url", Encoded: url.PathEscape(url.PathEscape(path))},
		{Name: "uppercase", Encoded: strings.ToUpper(path)},
		{Name: "null-byte", Encoded: path + "%00"},
	}

	// Unicode variant: replace / with %2F selectively
	unicode := strings.ReplaceAll(path, "/", "%2F")
	if unicode != path {
		variants = append(variants, EncodingVariant{Name: "slash-encoded", Encoded: unicode})
	}

	return variants
}

// SpELEncode encodes a SpEL expression with different obfuscation levels.
func SpELEncode(expr string) []string {
	return []string{
		expr,
		strings.ReplaceAll(expr, ".", "\u0000."),
		fmt.Sprintf("#{%s}", expr),
	}
}
