package models

import "time"

type BasicAuth struct {
	Username string
	Password string
}

type FingerprintData struct {
	FaviconHash      string
	FaviconMatchName string
	ErrorPageMatch   bool
	WhitelabelMatch  bool
	ServerHeader     string
	XAppContext      string
	Technologies     []string
	Confidence       int // 0-100
}

type Target struct {
	URL             string
	BaseURL         string
	Headers         map[string]string
	Proxy           string
	Insecure        bool
	Timeout         time.Duration
	Delay           time.Duration
	RateLimit       int
	BasicAuth       *BasicAuth
	BearerToken     string
	Cookies         string
	FollowRedirects bool
	CallbackHost    string
	IsSpringBoot    bool
	Fingerprint     *FingerprintData
}
