// Package config loads drift.yaml and fills every default, so later stages never check for zero values.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/akolomiiets/driftscan/internal/finding"
)

// DefaultExclude keeps provider caches, module examples and test fixtures out of discovery.
var DefaultExclude = []string{"**/.terraform/**", "**/examples/**", "**/testdata/**"}

type Config struct {
	Binary      string        `yaml:"binary"`
	Concurrency int           `yaml:"concurrency"`
	Timeout     time.Duration `yaml:"timeout"`
	// Include and Exclude are globs over Root paths relative to the scanned directory.
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
	// Roots are added even without a backend block (local state).
	Roots []string  `yaml:"roots"`
	Env   []EnvRule `yaml:"env"`
	// Workspaces lists the terraform workspaces to plan for matching Roots; the last matching rule wins.
	Workspaces []WorkspaceRule `yaml:"workspaces"`

	Pending  PendingConfig  `yaml:"pending"`
	Severity SeverityConfig `yaml:"severity"`
	Ignore   []IgnoreRule   `yaml:"ignore"`
	Noise    NoiseConfig    `yaml:"noise"`
	Slack    SlackConfig    `yaml:"slack"`
	OTLP     OTLPConfig     `yaml:"otlp"`
	Advisor  AdvisorConfig  `yaml:"advisor"`
}

type AdvisorConfig struct {
	// Model is the Bedrock model or inference profile id; required by driftscan advise, no default.
	Model string `yaml:"model"`
}

// EnvRule sets environment variables for the terraform processes of every Root matching Match.
// All matching rules apply in order; later ones win.
type EnvRule struct {
	Match string            `yaml:"match"`
	Vars  map[string]string `yaml:"vars"`
}

// WorkspaceRule makes every Root matching Match one Root per workspace, scanned as "path@name".
type WorkspaceRule struct {
	Match string   `yaml:"match"`
	Names []string `yaml:"names"`
}

type PendingConfig struct {
	Enabled  *bool            `yaml:"enabled"`
	Severity finding.Severity `yaml:"severity"`
}

type SeverityConfig struct {
	// Defaults turns the built-in rules on (the default) or off.
	Defaults *bool  `yaml:"defaults"`
	Rules    []Rule `yaml:"rules"`
}

// Rule matches by globs; empty fields match anything. The last matching rule wins.
type Rule struct {
	Type      string           `yaml:"type"`
	Address   string           `yaml:"address"`
	Attribute string           `yaml:"attribute"`
	Kind      finding.Kind     `yaml:"kind"`
	Severity  finding.Severity `yaml:"severity"`
}

// IgnoreRule drops matching Findings until Expires. Reason is required so every exception is explained.
type IgnoreRule struct {
	Type      string `yaml:"type"`
	Address   string `yaml:"address"`
	Root      string `yaml:"root"`
	Attribute string `yaml:"attribute"`
	Reason    string `yaml:"reason"`
	Expires   Date   `yaml:"expires"`
}

type NoiseConfig struct {
	// DigestAfter moves a persisting Finding out of Slack after this many Scans (0 = never).
	DigestAfter int `yaml:"digest_after"`
	// BrokenRootAfter collapses a Root's repeated Scan errors into one alert after this many Scans.
	BrokenRootAfter int `yaml:"broken_root_after"`
}

type SlackConfig struct {
	WebhookEnv string `yaml:"webhook_env"`
	// GroupBy is "root" (one message per Root) or "scan" (one message).
	GroupBy string `yaml:"group_by"`
}

type OTLPConfig struct {
	// EndpointEnv names the env var with the OTLP/HTTP metrics URL, e.g. https://host/v1/metrics.
	EndpointEnv string `yaml:"endpoint_env"`
	// HeadersEnv names an env var with "k=v,k2=v2" headers (OTEL_EXPORTER_OTLP_HEADERS format).
	HeadersEnv string `yaml:"headers_env"`
}

// Date is a YYYY-MM-DD day; the zero Date never expires.
type Date struct{ time.Time }

func (d *Date) UnmarshalYAML(n *yaml.Node) error {
	t, err := time.Parse(time.DateOnly, n.Value)
	if err != nil {
		return fmt.Errorf("line %d: expires must be YYYY-MM-DD: %w", n.Line, err)
	}
	d.Time = t
	return nil
}

// Expired reports whether the rule stopped applying at the start of now's day (UTC).
func (r IgnoreRule) Expired(now time.Time) bool {
	return !r.Expires.IsZero() && !now.UTC().Before(r.Expires.AddDate(0, 0, 1))
}

func (c PendingConfig) On() bool { return c.Enabled == nil || *c.Enabled }

func (c SeverityConfig) DefaultsOn() bool { return c.Defaults == nil || *c.Defaults }

func Default() Config {
	c := Config{}
	c.applyDefaults()
	return c
}

// Load reads path; a missing file at the default path yields Default().
func Load(path string, required bool) (Config, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && !required {
		return Default(), nil
	}
	if err != nil {
		return Config{}, err
	}
	return Parse(b)
}

func Parse(b []byte) (Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("drift.yaml: %w", err)
	}
	c.applyDefaults()
	return c, c.validate()
}

func (c *Config) applyDefaults() {
	if c.Binary == "" {
		c.Binary = "terraform"
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 4
	}
	if c.Timeout <= 0 {
		c.Timeout = 15 * time.Minute
	}
	if len(c.Include) == 0 {
		c.Include = []string{"**"}
	}
	c.Exclude = append(append([]string{}, DefaultExclude...), c.Exclude...)
	if c.Noise.BrokenRootAfter == 0 {
		c.Noise.BrokenRootAfter = 3
	}
	if c.Slack.WebhookEnv == "" {
		c.Slack.WebhookEnv = "SLACK_WEBHOOK_URL"
	}
	if c.Slack.GroupBy == "" {
		c.Slack.GroupBy = "scan"
	}
	if c.OTLP.EndpointEnv == "" {
		c.OTLP.EndpointEnv = "DRIFTSCAN_OTLP_ENDPOINT"
	}
	if c.OTLP.HeadersEnv == "" {
		c.OTLP.HeadersEnv = "DRIFTSCAN_OTLP_HEADERS"
	}
}

func (c Config) validate() error {
	var errs []error
	if c.Slack.GroupBy != "root" && c.Slack.GroupBy != "scan" {
		errs = append(errs, fmt.Errorf("slack.group_by must be root or scan, got %q", c.Slack.GroupBy))
	}
	for i, r := range c.Ignore {
		if r.Reason == "" {
			errs = append(errs, fmt.Errorf("ignore[%d]: reason is required", i))
		}
		if r.Type == "" && r.Address == "" && r.Root == "" && r.Attribute == "" {
			errs = append(errs, fmt.Errorf("ignore[%d]: set at least one of type, address, root, attribute", i))
		}
	}
	for i, r := range c.Env {
		if r.Match == "" {
			errs = append(errs, fmt.Errorf("env[%d]: match is required", i))
		}
	}
	for i, r := range c.Workspaces {
		if r.Match == "" || len(r.Names) == 0 {
			errs = append(errs, fmt.Errorf("workspaces[%d]: match and names are required", i))
		}
		for _, n := range r.Names {
			if n == "" || strings.ContainsAny(n, "@/ ") {
				errs = append(errs, fmt.Errorf("workspaces[%d]: invalid workspace name %q", i, n))
			}
		}
	}
	for i, r := range c.Severity.Rules {
		switch r.Kind {
		case "", finding.KindDrift, finding.KindPending:
		default:
			errs = append(errs, fmt.Errorf("severity.rules[%d]: kind must be drift or pending", i))
		}
	}
	return errors.Join(errs...)
}
