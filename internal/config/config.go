package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/authz"
	"gopkg.in/yaml.v3"
)

// Config represents the complete configuration structure
type Config struct {
	General       GeneralConfig       `yaml:"general"`
	Techniques    TechniquesConfig    `yaml:"techniques"`
	WAF           WAFConfig           `yaml:"waf"`
	Proxy         ProxyConfig         `yaml:"proxy"`
	Scoring       ScoringConfig       `yaml:"scoring"`
	Evasion       EvasionConfig       `yaml:"evasion"`
	Reporting     ReportingConfig     `yaml:"reporting"`
	Security      SecurityConfig      `yaml:"security"`
	Integration   IntegrationConfig   `yaml:"integration"`
	Authorization AuthorizationConfig `yaml:"authorization"`
	Intelligence  IntelligenceConfig  `yaml:"intelligence"`
	API           APIConfig           `yaml:"api"`
	Plugins       PluginsConfig       `yaml:"plugins"`
}

// AuthorizationConfig controls multi-session authorization testing.
type AuthorizationConfig struct {
	Enabled       bool                             `yaml:"enabled"`
	OpenAPI       string                           `yaml:"openapi"`
	Baseline      string                           `yaml:"baseline_session"`
	PathOverrides map[string]string                `yaml:"path_overrides"`
	Sessions      map[string]authz.CredentialsConfig `yaml:"sessions"`
}

// IntelligenceConfig controls the adaptive scoring and analysis features.
type IntelligenceConfig struct {
	Adaptive        bool    `yaml:"adaptive"`
	LearningFile    string  `yaml:"learning_file"`
	DependencyGraph bool    `yaml:"dependency_graph"`
	Behavioral      bool    `yaml:"behavioral"`
	Anomaly         bool    `yaml:"anomaly"`
	ConfidenceMin   float64 `yaml:"confidence_min"`
}

// APIConfig controls the REST API server.
type APIConfig struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	Token   string `yaml:"token"`
}

// PluginsConfig controls declarative plugin loading.
type PluginsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Dir     string `yaml:"dir"`
}

type GeneralConfig struct {
	Target         string        `yaml:"target"`
	Timeout        time.Duration `yaml:"timeout"`
	MaxRetries     int           `yaml:"max_retries"`
	DryRun         bool          `yaml:"dry_run"`
	Workers        int           `yaml:"workers"`
	RateLimit      int           `yaml:"rate_limit"`
	Burst          int           `yaml:"burst"`
	OutputPath     string        `yaml:"output_path"`
	Quiet          bool          `yaml:"quiet"`
	Verbose        bool          `yaml:"verbose"`
	LogLevel       string        `yaml:"log_level"`
	NoRetest       bool          `yaml:"no_retest"`
	ReplayAttempts int           `yaml:"replay_attempts"`
}

type TechniquesConfig struct {
	Enabled  []string       `yaml:"enabled"`
	Headers  HeadersConfig  `yaml:"headers"`
	Verbs    VerbsConfig    `yaml:"verbs"`
	Encoding EncodingConfig `yaml:"encoding"`
	Raw      RawConfig      `yaml:"raw"`
}

type HeadersConfig struct {
	BypassIP      string            `yaml:"bypass_ip"`
	CustomHeaders map[string]string `yaml:"custom_headers"`
}

type VerbsConfig struct {
	IncludeDangerous bool     `yaml:"include_dangerous"`
	CustomMethods    []string `yaml:"custom_methods"`
}

type EncodingConfig struct {
	DoubleEncode     bool `yaml:"double_encode"`
	MixedCase        bool `yaml:"mixed_case"`
	UnicodeNormalize bool `yaml:"unicode_normalize"`
}

type RawConfig struct {
	EnableDesync           bool `yaml:"enable_desync"`
	EnableDuplicateHeaders bool `yaml:"enable_duplicate_headers"`
	EnableAbsoluteURI      bool `yaml:"enable_absolute_uri"`
}

type WAFConfig struct {
	DetectionMode      string           `yaml:"detection_mode"`
	BypassMode         string           `yaml:"bypass_mode"`
	FrontendSignatures string           `yaml:"frontend_signatures"`
	WAFSignatures      string           `yaml:"waf_signatures"`
	Cloudflare         CloudflareConfig `yaml:"cloudflare"`
	Akamai             AkamaiConfig     `yaml:"akamai"`
}

type CloudflareConfig struct {
	EnableUARotation   bool `yaml:"enable_ua_rotation"`
	EnableCookieBypass bool `yaml:"enable_cookie_bypass"`
	ChallengeBypass    bool `yaml:"challenge_bypass"`
}

type AkamaiConfig struct {
	EnableEdgeAuth     bool `yaml:"enable_edge_auth"`
	EnableGhostHeaders bool `yaml:"enable_ghost_headers"`
}

type ProxyConfig struct {
	URL                string              `yaml:"url"`
	Rotation           ProxyRotationConfig `yaml:"rotation"`
	SupportedProtocols []string            `yaml:"supported_protocols"`
}

type ProxyRotationConfig struct {
	Enabled          bool   `yaml:"enabled"`
	ProxiesFile      string `yaml:"proxies_file"`
	RotationStrategy string `yaml:"rotation_strategy"`
	HealthCheck      bool   `yaml:"health_check"`
	Failover         bool   `yaml:"failover"`
}

type ScoringConfig struct {
	InterestingThreshold      int  `yaml:"interesting_threshold"`
	HighConfidenceThreshold   int  `yaml:"high_confidence_threshold"`
	CriticalThreshold         int  `yaml:"critical_threshold"`
	EnableMLScoring           bool `yaml:"enable_ml_scoring"`
	EnablePatternAnalysis     bool `yaml:"enable_pattern_analysis"`
	EnableSimilarityDetection bool `yaml:"enable_similarity_detection"`
	ReplayBonus               int  `yaml:"replay_bonus"`
	ReplayPenalty             int  `yaml:"replay_penalty"`
}

type EvasionConfig struct {
	UARotation          UARotationConfig          `yaml:"ua_rotation"`
	CookieManipulation  CookieManipulationConfig  `yaml:"cookie_manipulation"`
	Timing              TimingConfig              `yaml:"timing"`
	HeaderRandomization HeaderRandomizationConfig `yaml:"header_randomization"`
}

type UARotationConfig struct {
	Enabled          bool   `yaml:"enabled"`
	UAFile           string `yaml:"ua_file"`
	RotationStrategy string `yaml:"rotation_strategy"`
}

type CookieManipulationConfig struct {
	Enabled      bool `yaml:"enabled"`
	StripSession bool `yaml:"strip_session"`
	AddRandom    bool `yaml:"add_random"`
}

type TimingConfig struct {
	RandomDelays bool   `yaml:"random_delays"`
	DelayRange   string `yaml:"delay_range"`
	Jitter       bool   `yaml:"jitter"`
}

type HeaderRandomizationConfig struct {
	Enabled         bool `yaml:"enabled"`
	RandomOrder     bool `yaml:"random_order"`
	AddNoiseHeaders bool `yaml:"add_noise_headers"`
}

type ReportingConfig struct {
	Formats               []string      `yaml:"formats"`
	IncludeRequest        bool          `yaml:"include_request"`
	IncludeResponse       bool          `yaml:"include_response"`
	IncludeHeaders        bool          `yaml:"include_headers"`
	IncludeTiming         bool          `yaml:"include_timing"`
	IncludeScoreBreakdown bool          `yaml:"include_score_breakdown"`
	Webhook               WebhookConfig `yaml:"webhook"`
}

type WebhookConfig struct {
	Enabled       bool              `yaml:"enabled"`
	URL           string            `yaml:"url"`
	Method        string            `yaml:"method"`
	Headers       map[string]string `yaml:"headers"`
	OnSuccessOnly bool              `yaml:"on_success_only"`
}

type SecurityConfig struct {
	AdaptiveRateLimiting bool          `yaml:"adaptive_rate_limiting"`
	BackoffOnError       bool          `yaml:"backoff_on_error"`
	MaxErrorsBeforePause int           `yaml:"max_errors_before_pause"`
	RandomizeTiming      bool          `yaml:"randomize_timing"`
	RandomizeHeaders     bool          `yaml:"randomize_headers"`
	MaxRequestsPerTarget int           `yaml:"max_requests_per_target"`
	MaxDuration          time.Duration `yaml:"max_duration"`
}

type IntegrationConfig struct {
	CICD      CICDConfig      `yaml:"cicd"`
	Platforms PlatformsConfig `yaml:"platforms"`
}

type CICDConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Format    string `yaml:"format"`
	OutputDir string `yaml:"output_dir"`
}

type PlatformsConfig struct {
	Slack  SlackConfig  `yaml:"slack"`
	Jira   JiraConfig   `yaml:"jira"`
	GitHub GitHubConfig `yaml:"github"`
}

type SlackConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
	Channel    string `yaml:"channel"`
}

type JiraConfig struct {
	Enabled   bool   `yaml:"enabled"`
	APIURL    string `yaml:"api_url"`
	Project   string `yaml:"project"`
	IssueType string `yaml:"issue_type"`
}

type GitHubConfig struct {
	Enabled          bool   `yaml:"enabled"`
	Token            string `yaml:"token"`
	Repo             string `yaml:"repo"`
	AutoCreateIssues bool   `yaml:"auto_create_issues"`
}

// Load loads configuration from a YAML file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults if not specified
	setDefaults(&cfg)

	return &cfg, nil
}

// LoadOrDefault loads config from path or returns default config
func LoadOrDefault(path string) (*Config, error) {
	if path == "" {
		// Try default locations
		defaultPaths := []string{
			"config.yaml",
			"bypass403.yaml",
			".bypass403.yaml",
			"config/default.yaml",
		}

		for _, p := range defaultPaths {
			if _, err := os.Stat(p); err == nil {
				return Load(p)
			}
		}

		// Return default config
		return DefaultConfig(), nil
	}

	return Load(path)
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		General: GeneralConfig{
			Timeout:        10 * time.Second,
			MaxRetries:     2,
			DryRun:         false,
			Workers:        20,
			RateLimit:      100,
			Burst:          50,
			Quiet:          false,
			Verbose:        false,
			LogLevel:       "info",
			NoRetest:       false,
			ReplayAttempts: 2,
		},
		Techniques: TechniquesConfig{
			Enabled: []string{"headers", "verbs", "endpaths", "midpaths", "encoding"},
			Headers: HeadersConfig{
				BypassIP:      "127.0.0.1",
				CustomHeaders: make(map[string]string),
			},
			Verbs: VerbsConfig{
				IncludeDangerous: true,
				CustomMethods:    []string{},
			},
			Encoding: EncodingConfig{
				DoubleEncode:     true,
				MixedCase:        true,
				UnicodeNormalize: true,
			},
			Raw: RawConfig{
				EnableDesync:           true,
				EnableDuplicateHeaders: true,
				EnableAbsoluteURI:      true,
			},
		},
		WAF: WAFConfig{
			DetectionMode:      "normal",
			BypassMode:         "standard",
			FrontendSignatures: "config/frontend_signatures.json",
			WAFSignatures:      "config/waf_signatures.json",
		},
		Scoring: ScoringConfig{
			InterestingThreshold:      40,
			HighConfidenceThreshold:   70,
			CriticalThreshold:         90,
			EnableMLScoring:           false,
			EnablePatternAnalysis:     true,
			EnableSimilarityDetection: true,
			ReplayBonus:               10,
			ReplayPenalty:             -20,
		},
		Security: SecurityConfig{
			AdaptiveRateLimiting: true,
			BackoffOnError:       true,
			MaxErrorsBeforePause: 10,
			RandomizeTiming:      true,
			RandomizeHeaders:     true,
			MaxRequestsPerTarget: 10000,
			MaxDuration:          time.Hour,
		},
	}
}

func setDefaults(cfg *Config) {
	if cfg.General.Timeout == 0 {
		cfg.General.Timeout = 10 * time.Second
	}
	if cfg.General.Workers == 0 {
		cfg.General.Workers = 20
	}
	if cfg.General.RateLimit == 0 {
		cfg.General.RateLimit = 100
	}
	if cfg.General.Burst == 0 {
		cfg.General.Burst = min(cfg.General.RateLimit, 50)
	}
	if cfg.Security.MaxRequestsPerTarget == 0 {
		cfg.Security.MaxRequestsPerTarget = 10000
	}
	if cfg.Security.MaxDuration == 0 {
		cfg.Security.MaxDuration = time.Hour
	}
	if cfg.General.LogLevel == "" {
		cfg.General.LogLevel = "info"
	}
	if cfg.WAF.DetectionMode == "" {
		cfg.WAF.DetectionMode = "normal"
	}
	if cfg.WAF.BypassMode == "" {
		cfg.WAF.BypassMode = "standard"
	}
}

func (cfg *Config) Validate() error {
	if cfg.General.Timeout <= 0 {
		return fmt.Errorf("general.timeout must be positive")
	}
	if cfg.General.Workers < 1 || cfg.General.Workers > 1024 {
		return fmt.Errorf("general.workers must be between 1 and 1024")
	}
	if cfg.General.RateLimit < 1 {
		return fmt.Errorf("general.rate_limit must be positive")
	}
	if cfg.General.Burst < 1 || cfg.General.Burst > 10000 {
		return fmt.Errorf("general.burst must be between 1 and 10000")
	}
	if cfg.General.MaxRetries < 0 || cfg.General.MaxRetries > 10 {
		return fmt.Errorf("general.max_retries must be between 0 and 10")
	}
	if cfg.Security.MaxRequestsPerTarget < 1 {
		return fmt.Errorf("security.max_requests_per_target must be positive")
	}
	if cfg.Security.MaxDuration <= 0 {
		return fmt.Errorf("security.max_duration must be positive")
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Save saves configuration to a YAML file
func Save(cfg *Config, path string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
