package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/springhawk/springhawk/assets"
	"github.com/springhawk/springhawk/internal/config"
	"github.com/springhawk/springhawk/internal/engine"
	httpclient "github.com/springhawk/springhawk/internal/http"
	"github.com/springhawk/springhawk/internal/reporting"
	"github.com/springhawk/springhawk/pkg/models"
	"github.com/springhawk/springhawk/pkg/utils"

	// Import all vulnerability modules to trigger init() registration
	_ "github.com/springhawk/springhawk/internal/vulns/cve"
	_ "github.com/springhawk/springhawk/internal/vulns/web"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Active remote scanning — endpoint discovery + vulnerability testing",
	Example: `  springhawk scan -t https://myapp.com
  springhawk scan -t https://myapp.com --exploit --callback-host my.oast.host
  springhawk scan -f targets.txt --workers 50 --format json -o results.json
  springhawk scan -t https://myapp.com -p socks5://127.0.0.1:9050 --profile stealth`,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	f := scanCmd.Flags()
	f.StringP("target", "t", "", "single target URL")
	f.StringP("file", "f", "", "file with target URLs (one per line)")
	f.StringP("proxy", "p", "", "proxy URL: http://host:port or socks5://host:port")
	f.StringArrayP("header", "H", nil, "custom HTTP header (repeatable)")
	f.Int("timeout", 10, "request timeout in seconds")
	f.Int("workers", 20, "concurrent goroutine workers")
	f.Int("delay", 0, "delay between requests in milliseconds")
	f.Int("rate-limit", 50, "max requests per second per host")
	f.Bool("insecure", true, "skip TLS certificate verification")
	f.Bool("skip-fingerprint", false, "skip Spring Boot fingerprinting")
	f.Bool("exploit", false, "enable active exploitation (webshell, RCE)")
	f.String("callback-host", "", "OAST callback host for blind vulnerabilities")
	f.Bool("download-heapdump", false, "auto-download heapdump if found")
	f.String("output-dir", "springhawk-output", "directory for downloaded files")
	f.String("profile", "standard", "scan profile: aggressive|standard|stealth|safe")
	f.String("modules", "", "comma-separated module IDs to run (default: all)")
	f.String("skip-modules", "", "comma-separated module IDs to skip")
	f.String("cookie", "", "cookie header value")
	f.String("bearer-token", "", "bearer token for Authorization header")
}

func runScan(cmd *cobra.Command, args []string) error {
	reporting.PrintBanner(os.Stdout)

	cfg := buildScanConfig(cmd)

	client, err := httpclient.NewClient(&httpclient.ClientConfig{
		ProxyURL:     cfg.Proxy,
		InsecureTLS:  cfg.Insecure,
		Timeout:      cfg.Timeout,
		UAMode:       "rotate",
		RetryCount:   2,
		RetryBackoff: 500 * time.Millisecond,
	})
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

	limiter := engine.NewRateLimiter(cfg.RateLimit, cfg.Delay)
	endpoints, err := assets.Endpoints()
	if err != nil {
		return fmt.Errorf("failed to load endpoint wordlist: %w", err)
	}

	opts := &engine.ScanOptions{
		Workers:         cfg.Workers,
		SkipFingerprint: cfg.SkipFingerprint,
		Exploit:         cfg.Exploit,
		EndpointList:    endpoints,
	}
	if cfg.Modules != nil {
		opts.Modules = cfg.Modules
	}

	scanner := engine.NewScanner(client, limiter, opts)

	// Collect targets
	targets, err := collectTargets(cmd, cfg)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified. Use -t <URL> or -f <file>")
	}

	format, _ := cmd.Root().PersistentFlags().GetString("format")
	outFile, _ := cmd.Root().PersistentFlags().GetString("output")

	w := os.Stdout
	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			return fmt.Errorf("cannot create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	ctx := context.Background()
	reporter := &reporting.JSONReporter{Indent: true}

	for _, targetURL := range targets {
		targetURL = utils.NormalizeURL(targetURL)
		color.New(color.FgCyan, color.Bold).Fprintf(os.Stderr, "\n[*] Scanning: %s\n", targetURL)

		target := &models.Target{
			URL:             targetURL,
			BaseURL:         targetURL,
			IsSpringBoot:    false,
			Headers:         cfg.ExtraHeaders,
			Proxy:           cfg.Proxy,
			Insecure:        cfg.Insecure,
			Timeout:         cfg.Timeout,
			Delay:           cfg.Delay,
			RateLimit:       cfg.RateLimit,
			FollowRedirects: cfg.FollowRedirects,
			CallbackHost:    cfg.CallbackHost,
			Cookies:         cfg.Cookies,
			BearerToken:     cfg.BearerToken,
		}

		result := scanner.Scan(ctx, target)

		switch format {
		case "json":
			reporter.WriteScanResult(result, w) //nolint:errcheck
		default:
			for _, f := range result.Findings {
				reporting.PrintFinding(os.Stdout, f)
			}
			reporting.PrintScanSummary(os.Stdout, result)
		}
	}
	return nil
}

func collectTargets(cmd *cobra.Command, cfg *config.Config) ([]string, error) {
	var targets []string

	if t, _ := cmd.Flags().GetString("target"); t != "" {
		targets = append(targets, t)
	}
	if file, _ := cmd.Flags().GetString("file"); file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("cannot open target file: %w", err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
	}
	return targets, nil
}

func buildScanConfig(cmd *cobra.Command) *config.Config {
	cfg := config.Default()

	timeout, _ := cmd.Flags().GetInt("timeout")
	cfg.Timeout = time.Duration(timeout) * time.Second

	cfg.Workers, _ = cmd.Flags().GetInt("workers")
	delayMs, _ := cmd.Flags().GetInt("delay")
	cfg.Delay = time.Duration(delayMs) * time.Millisecond
	cfg.RateLimit, _ = cmd.Flags().GetInt("rate-limit")
	cfg.Proxy, _ = cmd.Flags().GetString("proxy")
	cfg.Insecure, _ = cmd.Flags().GetBool("insecure")
	cfg.SkipFingerprint, _ = cmd.Flags().GetBool("skip-fingerprint")
	cfg.Exploit, _ = cmd.Flags().GetBool("exploit")
	cfg.CallbackHost, _ = cmd.Flags().GetString("callback-host")
	cfg.Cookies, _ = cmd.Flags().GetString("cookie")
	cfg.BearerToken, _ = cmd.Flags().GetString("bearer-token")
	cfg.FollowRedirects = true

	// Custom headers
	headers, _ := cmd.Flags().GetStringArray("header")
	if len(headers) > 0 {
		cfg.ExtraHeaders = make(map[string]string)
		for _, h := range headers {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				cfg.ExtraHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}
	if cfg.BearerToken != "" {
		if cfg.ExtraHeaders == nil {
			cfg.ExtraHeaders = make(map[string]string)
		}
		cfg.ExtraHeaders["Authorization"] = "Bearer " + cfg.BearerToken
	}
	if cfg.Cookies != "" {
		if cfg.ExtraHeaders == nil {
			cfg.ExtraHeaders = make(map[string]string)
		}
		cfg.ExtraHeaders["Cookie"] = cfg.Cookies
	}

	// Apply profile
	if profile, _ := cmd.Flags().GetString("profile"); profile != "" {
		config.ApplyProfile(cfg, config.Profile(profile))
	}

	// Module filter
	if mods, _ := cmd.Flags().GetString("modules"); mods != "" {
		cfg.Modules = strings.Split(mods, ",")
	}

	_ = json.Marshal // ensure json import used
	return cfg
}
