package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type ClientConfig struct {
	ProxyURL        string
	InsecureTLS     bool
	Timeout         time.Duration
	MaxRedirects    int
	UAMode          string // "rotate" | "fixed" | "custom"
	CustomUA        string
	ExtraHeaders    map[string]string
	RetryCount      int
	RetryBackoff    time.Duration
}

type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	BodyString string
	URL        string
	Duration   time.Duration
}

type Client struct {
	inner    *http.Client
	cfg      *ClientConfig
	rotator  *UARotator
}

func NewClient(cfg *ClientConfig) (*Client, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxRedirects == 0 {
		cfg.MaxRedirects = 5
	}

	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.InsecureTLS} //nolint:gosec

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		TLSClientConfig:     tlsCfg,
		DialContext:         dialer.DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  false,
	}

	if cfg.ProxyURL != "" {
		if strings.HasPrefix(cfg.ProxyURL, "socks5://") {
			auth := &proxy.Auth{}
			u, err := url.Parse(cfg.ProxyURL)
			if err != nil {
				return nil, fmt.Errorf("invalid proxy URL: %w", err)
			}
			if u.User != nil {
				auth.User = u.User.Username()
				auth.Password, _ = u.User.Password()
			}
			host := u.Host
			dialer, err := proxy.SOCKS5("tcp", host, auth, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("socks5 proxy: %w", err)
			}
			dc, ok := dialer.(proxy.ContextDialer)
			if ok {
				transport.DialContext = dc.DialContext
			}
		} else {
			proxyURL, err := url.Parse(cfg.ProxyURL)
			if err != nil {
				return nil, fmt.Errorf("invalid proxy URL: %w", err)
			}
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	inner := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= cfg.MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return &Client{inner: inner, cfg: cfg, rotator: NewUARotator()}, nil
}

func (c *Client) do(ctx context.Context, method, rawURL string, body io.Reader, extraHeaders map[string]string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}

	// User-Agent
	switch c.cfg.UAMode {
	case "fixed":
		req.Header.Set("User-Agent", c.cfg.CustomUA)
	case "rotate":
		req.Header.Set("User-Agent", c.rotator.Next())
	default:
		req.Header.Set("User-Agent", c.rotator.Next())
	}

	// Global extra headers
	for k, v := range c.cfg.ExtraHeaders {
		req.Header.Set(k, v)
	}
	// Per-request extra headers
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	start := time.Now()
	var resp *http.Response
	var doErr error

	retries := c.cfg.RetryCount
	if retries == 0 {
		retries = 1
	}
	for i := 0; i < retries; i++ {
		resp, doErr = c.inner.Do(req)
		if doErr == nil {
			break
		}
		if i < retries-1 && c.cfg.RetryBackoff > 0 {
			time.Sleep(c.cfg.RetryBackoff)
		}
	}
	if doErr != nil {
		return nil, doErr
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       respBody,
		BodyString: string(respBody),
		URL:        resp.Request.URL.String(),
		Duration:   time.Since(start),
	}, nil
}

func (c *Client) Get(ctx context.Context, rawURL string, headers map[string]string) (*Response, error) {
	return c.do(ctx, http.MethodGet, rawURL, nil, headers)
}

func (c *Client) Post(ctx context.Context, rawURL, contentType string, body io.Reader, headers map[string]string) (*Response, error) {
	h := map[string]string{"Content-Type": contentType}
	for k, v := range headers {
		h[k] = v
	}
	return c.do(ctx, http.MethodPost, rawURL, body, h)
}

func (c *Client) Delete(ctx context.Context, rawURL string, headers map[string]string) (*Response, error) {
	return c.do(ctx, http.MethodDelete, rawURL, nil, headers)
}

func (c *Client) Download(ctx context.Context, rawURL, destPath string) (int64, error) {
	resp, err := c.Get(ctx, rawURL, nil)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	// Write to dest via io utilities in caller — return body length
	return int64(len(resp.Body)), nil
}
