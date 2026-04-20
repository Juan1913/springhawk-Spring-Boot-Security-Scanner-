package config

import (
	"time"

	"github.com/spf13/viper"
)

type Profile string

const (
	ProfileAggressive Profile = "aggressive"
	ProfileStandard   Profile = "standard"
	ProfileStealth    Profile = "stealth"
	ProfileSafe       Profile = "safe"
)

type Config struct {
	Workers         int
	Timeout         time.Duration
	Delay           time.Duration
	RateLimit       int
	Proxy           string
	Insecure        bool
	FollowRedirects bool
	UserAgent       string
	ExtraHeaders    map[string]string
	Cookies         string
	BearerToken     string
	BasicAuth       string
	CallbackHost    string

	Exploit          bool
	DownloadHeapdump bool
	OutputDir        string
	SkipFingerprint  bool
	Modules          []string
	SkipModules      []string

	OutputFile   string
	OutputFormat string
	Verbose      bool
	Quiet        bool
	NoColor      bool

	APIKeys APIKeys
}

type APIKeys struct {
	ZoomEye     string
	FofaEmail   string
	FofaKey     string
	Hunter      string
	Shodan      string
	CensysID    string
	CensysSecret string
}

var profileDefaults = map[Profile]*Config{
	ProfileAggressive: {Workers: 50, RateLimit: 200, Timeout: 8 * time.Second},
	ProfileStandard:   {Workers: 20, RateLimit: 50, Timeout: 10 * time.Second},
	ProfileStealth:    {Workers: 3, RateLimit: 5, Timeout: 15 * time.Second, Delay: 2000 * time.Millisecond},
	ProfileSafe:       {Workers: 10, RateLimit: 20, Timeout: 10 * time.Second},
}

func Default() *Config {
	return &Config{
		Workers:         20,
		Timeout:         10 * time.Second,
		RateLimit:       50,
		FollowRedirects: true,
		OutputFormat:    "terminal",
	}
}

func ApplyProfile(cfg *Config, profile Profile) {
	p, ok := profileDefaults[profile]
	if !ok {
		return
	}
	cfg.Workers = p.Workers
	cfg.RateLimit = p.RateLimit
	cfg.Timeout = p.Timeout
	if p.Delay > 0 {
		cfg.Delay = p.Delay
	}
}

func LoadFromViper(cfg *Config) {
	if v := viper.GetInt("defaults.workers"); v > 0 {
		cfg.Workers = v
	}
	if v := viper.GetInt("defaults.timeout"); v > 0 {
		cfg.Timeout = time.Duration(v) * time.Second
	}
	if v := viper.GetInt("defaults.rate_limit"); v > 0 {
		cfg.RateLimit = v
	}
	if v := viper.GetString("defaults.format"); v != "" {
		cfg.OutputFormat = v
	}
	cfg.APIKeys.ZoomEye = viper.GetString("api_keys.zoomeye")
	cfg.APIKeys.FofaEmail = viper.GetString("api_keys.fofa_email")
	cfg.APIKeys.FofaKey = viper.GetString("api_keys.fofa_key")
	cfg.APIKeys.Hunter = viper.GetString("api_keys.hunter")
	cfg.APIKeys.Shodan = viper.GetString("api_keys.shodan")
	cfg.APIKeys.CensysID = viper.GetString("api_keys.censys_id")
	cfg.APIKeys.CensysSecret = viper.GetString("api_keys.censys_secret")
}
