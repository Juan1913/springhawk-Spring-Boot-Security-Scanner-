package fingerprint

import (
	"context"
	"fmt"
	"strings"

	httpclient "github.com/springhawk/springhawk/internal/http"
	"github.com/springhawk/springhawk/pkg/models"
	"github.com/springhawk/springhawk/pkg/utils"
)

type Detector struct {
	client *httpclient.Client
}

func NewDetector(client *httpclient.Client) *Detector {
	return &Detector{client: client}
}

// Run performs all fingerprinting checks and returns a FingerprintData.
// Confidence 0-100 indicates how certain we are the target is Spring Boot.
func (d *Detector) Run(ctx context.Context, baseURL string) *models.FingerprintData {
	fp := &models.FingerprintData{}

	// Method 1: favicon hash
	faviconHash, matchName := checkFavicon(ctx, d.client, baseURL)
	if faviconHash != "" {
		fp.FaviconHash = faviconHash
		fp.FaviconMatchName = matchName
		if matchName != "" {
			fp.Confidence += 60
		}
	}

	// Method 2: error page JSON timestamp
	if checkErrorPage(ctx, d.client, baseURL) {
		fp.ErrorPageMatch = true
		fp.Confidence += 30
	}

	// Method 3: Whitelabel Error Page
	if checkWhitelabel(ctx, d.client, baseURL) {
		fp.WhitelabelMatch = true
		fp.Confidence += 20
	}

	// Method 4: headers
	srv, xapp := checkHeaders(ctx, d.client, baseURL)
	fp.ServerHeader = srv
	fp.XAppContext = xapp
	if xapp != "" {
		fp.Confidence += 20
	}

	if fp.Confidence > 100 {
		fp.Confidence = 100
	}

	if fp.Confidence >= 30 {
		fp.Technologies = append(fp.Technologies, "Spring Boot")
	}

	return fp
}

func checkFavicon(ctx context.Context, client *httpclient.Client, base string) (hash, matchName string) {
	resp, err := client.Get(ctx, utils.JoinURL(base, "favicon.ico"), nil)
	if err != nil || resp.StatusCode != 200 {
		return "", ""
	}
	ct := resp.Headers.Get("Content-Type")
	if !strings.Contains(ct, "image") && !strings.Contains(ct, "octet-stream") {
		return "", ""
	}
	h := utils.MurmurHash2(resp.Body)
	hashStr := hashToString(h)
	name := faviconDB[hashStr]
	return hashStr, name
}

func checkErrorPage(ctx context.Context, client *httpclient.Client, base string) bool {
	// Request a non-existent path to trigger Spring's 404 JSON error
	resp, err := client.Get(ctx, utils.JoinURL(base, "AabyssZG_springhawk_404_probe"), nil)
	if err != nil {
		return false
	}
	body := resp.BodyString
	return strings.Contains(body, `"timestamp"`) &&
		(strings.Contains(body, `"status"`) || strings.Contains(body, `"error"`))
}

func checkWhitelabel(ctx context.Context, client *httpclient.Client, base string) bool {
	resp, err := client.Get(ctx, utils.JoinURL(base, "error"), nil)
	if err != nil {
		return false
	}
	return strings.Contains(resp.BodyString, "Whitelabel Error Page") ||
		strings.Contains(resp.BodyString, "This application has no explicit mapping")
}

func checkHeaders(ctx context.Context, client *httpclient.Client, base string) (server, xapp string) {
	resp, err := client.Get(ctx, base, nil)
	if err != nil {
		return "", ""
	}
	server = resp.Headers.Get("Server")
	xapp = resp.Headers.Get("X-Application-Context")
	return server, xapp
}

func hashToString(h int32) string {
	return strings.ToLower(fmt.Sprintf("%d", h))
}

// faviconDB maps MurmurHash2 (as decimal string) to known app name.
var faviconDB = map[string]string{
	"-368174948":  "Spring Boot Default",
	"116323821":   "Spring Boot Alt",
	"1042618440":  "Spring Framework",
	"-1424556438": "Spring Boot Admin",
}

