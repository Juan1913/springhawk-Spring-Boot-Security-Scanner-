package engine

import (
	"bufio"
	"context"
	"crypto/md5"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/springhawk/springhawk/internal/fingerprint"
	httpclient "github.com/springhawk/springhawk/internal/http"
	"github.com/springhawk/springhawk/internal/vulns"
	"github.com/springhawk/springhawk/pkg/models"
	"github.com/springhawk/springhawk/pkg/utils"
)

type ScanOptions struct {
	Workers         int
	SkipFingerprint bool
	Exploit         bool
	Modules         []string // empty = all
	SkipModules     []string
	EndpointList    []string
}

type Scanner struct {
	client      *httpclient.Client
	detector    *fingerprint.Detector
	rateLimiter *RateLimiter
	opts        *ScanOptions
}

func NewScanner(client *httpclient.Client, rateLimiter *RateLimiter, opts *ScanOptions) *Scanner {
	return &Scanner{
		client:      client,
		detector:    fingerprint.NewDetector(client),
		rateLimiter: rateLimiter,
		opts:        opts,
	}
}

// Scan executes the full 3-phase scan against a target and returns results.
func (s *Scanner) Scan(ctx context.Context, target *models.Target) *models.ScanResult {
	result := &models.ScanResult{
		ScanID:    fmt.Sprintf("scan-%d", time.Now().UnixNano()),
		Target:    target,
		StartTime: time.Now(),
		Stats:     models.ScanStats{FindingsBySeverity: make(map[models.Severity]int)},
	}

	// Phase 1: Fingerprinting
	if !s.opts.SkipFingerprint {
		fp := s.detector.Run(ctx, target.BaseURL)
		target.Fingerprint = fp
		target.IsSpringBoot = fp.Confidence >= 30
		result.Fingerprint = fp
		result.IsSpringBoot = target.IsSpringBoot
	} else {
		target.IsSpringBoot = true
		result.IsSpringBoot = true
	}

	// Phase 2: Endpoint discovery
	endpointFindings := s.scanEndpoints(ctx, target)
	result.Findings = append(result.Findings, endpointFindings...)

	// Phase 3: Vulnerability modules
	vulnFindings := s.runModules(ctx, target)
	result.Findings = append(result.Findings, vulnFindings...)

	// Stats
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	for _, f := range result.Findings {
		result.Stats.FindingsBySeverity[f.Severity]++
	}
	result.Stats.TotalModules = len(vulns.Default.AllRemote())

	return result
}

func (s *Scanner) scanEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	endpoints := s.opts.EndpointList

	type endpointResult struct {
		url        string
		statusCode int
		bodyHash   string
		bodySnip   string
		length     int
	}

	var (
		mu       sync.Mutex
		findings []*models.Finding
		seen     = make(map[string]bool) // dedup by body hash
		counter  atomic.Int64
	)

	pool := NewWorkerPool[string, *endpointResult](
		s.opts.Workers, len(endpoints),
		func(ctx context.Context, job Job[string]) (*endpointResult, error) {
			u := utils.JoinURL(target.BaseURL, job.Payload)
			host := utils.ExtractHost(u)
			if err := s.rateLimiter.Wait(ctx, host); err != nil {
				return nil, err
			}
			resp, err := s.client.Get(ctx, u, nil)
			if err != nil {
				return nil, nil
			}
			counter.Add(1)
			hash := fmt.Sprintf("%x", md5.Sum(resp.Body))
			snip := resp.BodyString
			if len(snip) > 300 {
				snip = snip[:300]
			}
			return &endpointResult{
				url:        u,
				statusCode: resp.StatusCode,
				bodyHash:   hash,
				bodySnip:   snip,
				length:     len(resp.Body),
			}, nil
		},
	)

	pool.Start(ctx)

	go func() {
		for _, ep := range endpoints {
			pool.Submit(Job[string]{ID: ep, Payload: ep})
		}
		pool.Close()
		pool.Wait()
	}()

	for res := range pool.Results() {
		if res.Err != nil || res.Value == nil {
			continue
		}
		r := res.Value
		if r.statusCode != 200 {
			continue
		}
		if r.length < 5 {
			continue
		}
		// Filter common false positives
		lower := strings.ToLower(r.bodySnip)
		if strings.Contains(lower, "need login") ||
			strings.Contains(lower, "forbidden") ||
			strings.Contains(lower, "authentication required") {
			continue
		}
		mu.Lock()
		if seen[r.bodyHash] {
			mu.Unlock()
			continue
		}
		seen[r.bodyHash] = true
		mu.Unlock()

		ep := strings.TrimPrefix(r.url, target.BaseURL)
		f := &models.Finding{
			ID:          fmt.Sprintf("endpoint-%s-%d", sanitizeID(ep), time.Now().UnixNano()),
			Type:        models.FindingTypeExpose,
			Severity:    classifyEndpointSeverity(ep),
			Title:       fmt.Sprintf("Sensitive Endpoint Exposed: %s", ep),
			URL:         r.url,
			Endpoint:    ep,
			Method:      "GET",
			Evidence:    fmt.Sprintf("HTTP 200, %d bytes. Snippet: %s", r.length, truncateStr(r.bodySnip, 150)),
			Remediation: "Restrict access to sensitive endpoints via Spring Security. Set management.endpoints.web.exposure.include to only required endpoints.",
			Tags:        []string{"exposure", "actuator"},
			Timestamp:   time.Now(),
			ModuleID:    "endpoint-scanner",
		}
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
	}

	return findings
}

func (s *Scanner) runModules(ctx context.Context, target *models.Target) []*models.Finding {
	modules := s.filterModules(vulns.Default.AllRemote(), target)
	var (
		mu       sync.Mutex
		findings []*models.Finding
		wg       sync.WaitGroup
	)

	sem := make(chan struct{}, s.opts.Workers)
	for _, mod := range modules {
		wg.Add(1)
		mod := mod
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			var ff []*models.Finding
			var err error
			if s.opts.Exploit {
				ff, err = mod.Exploit(ctx, target, s.client)
			} else {
				ff, err = mod.Check(ctx, target, s.client)
			}
			if err != nil || len(ff) == 0 {
				return
			}
			mu.Lock()
			findings = append(findings, ff...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return findings
}

func (s *Scanner) filterModules(all []vulns.VulnModule, target *models.Target) []vulns.VulnModule {
	skip := make(map[string]bool)
	for _, id := range s.opts.SkipModules {
		skip[id] = true
	}
	allow := make(map[string]bool)
	for _, id := range s.opts.Modules {
		allow[id] = true
	}

	var out []vulns.VulnModule
	for _, m := range all {
		if skip[m.ID()] {
			continue
		}
		if len(allow) > 0 && !allow[m.ID()] {
			continue
		}
		req := m.Requirements()
		if req.MinConfidence > 0 && target.Fingerprint != nil && target.Fingerprint.Confidence < req.MinConfidence {
			continue
		}
		if req.RequiresCallback && target.CallbackHost == "" {
			continue
		}
		out = append(out, m)
	}
	return out
}

func classifyEndpointSeverity(ep string) models.Severity {
	ep = strings.ToLower(ep)
	criticalPaths := []string{"heapdump", "env", "configprops", "httptrace", "auditevents"}
	highPaths := []string{"beans", "mappings", "threaddump", "logfile", "jolokia", "h2-console"}
	for _, p := range criticalPaths {
		if strings.Contains(ep, p) {
			return models.SeverityCritical
		}
	}
	for _, p := range highPaths {
		if strings.Contains(ep, p) {
			return models.SeverityHigh
		}
	}
	return models.SeverityMedium
}

func sanitizeID(s string) string {
	r := strings.NewReplacer("/", "-", "?", "", "&", "", "=", "")
	return strings.Trim(r.Replace(s), "-")
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// LoadEndpoints parses a newline-separated list of endpoints.
func LoadEndpoints(data string) []string {
	var out []string
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}
