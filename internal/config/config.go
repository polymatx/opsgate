// Package config loads and validates the opsgate YAML configuration.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Mode controls how much an agent is allowed to do.
type Mode string

const (
	// ModeObserve allows read-only tools.
	ModeObserve Mode = "observe"
	// ModeOperate allows read-only tools freely and mutating tools behind approval.
	ModeOperate Mode = "operate"
	// ModeFull allows everything without approval. Still audited.
	ModeFull Mode = "full"
)

// Host is a target machine opsgate can operate on.
type Host struct {
	// Addr is the SSH address (host or host:port). Empty for the implicit local host.
	Addr string `yaml:"addr"`
	User string `yaml:"user"`
	// Key is the path to a private key. Falls back to ssh-agent, then default keys.
	Key string `yaml:"key"`
	// Mode overrides the global mode for this host.
	Mode Mode `yaml:"mode"`
	Port int  `yaml:"port"`
}

// ToolRule tunes policy for a single tool.
type ToolRule struct {
	// Enabled=false removes the tool entirely. Defaults to true except shell_exec.
	Enabled *bool `yaml:"enabled"`
	// AllowTargets restricts which targets (service names, container names,
	// units, paths) the tool may touch. Glob patterns. Empty = all.
	AllowTargets []string `yaml:"allow_targets"`
	// Approval: "always", "never", or "" (default by mode: mutating tools
	// require approval in operate mode).
	Approval string `yaml:"approval"`
}

// Audit configures the audit log.
type Audit struct {
	Path string `yaml:"path"`
	// RedactKeys are argument keys whose values are masked in the log.
	RedactKeys []string `yaml:"redact_keys"`
}

// Files configures the file_read / dir_list tools.
type Files struct {
	// AllowPaths are glob-ish path prefixes readable by file tools.
	AllowPaths []string `yaml:"allow_paths"`
	// MaxBytes caps file_read output. Default 64 KiB.
	MaxBytes int64 `yaml:"max_bytes"`
}

// HTTP configures the streamable HTTP transport.
type HTTP struct {
	Addr string `yaml:"addr"`
	// AuthToken is required as "Authorization: Bearer <token>" when set.
	AuthToken string `yaml:"auth_token"`
}

// Config is the root configuration.
type Config struct {
	Mode        Mode                `yaml:"mode"`
	DefaultHost string              `yaml:"default_host"`
	Hosts       map[string]Host     `yaml:"hosts"`
	Tools       map[string]ToolRule `yaml:"tools"`
	Audit       Audit               `yaml:"audit"`
	Files       Files               `yaml:"files"`
	HTTP        HTTP                `yaml:"http"`
	// TimeoutSeconds is the per-command timeout. Default 30.
	TimeoutSeconds int `yaml:"timeout_seconds"`
	// MaxOutputBytes caps tool output returned to the model. Default 48 KiB.
	MaxOutputBytes int `yaml:"max_output_bytes"`
}

// Default returns the built-in configuration used when no file exists:
// local host only, observe mode, audit to ~/.opsgate/audit.jsonl.
func Default() *Config {
	c := &Config{
		Mode:        ModeObserve,
		DefaultHost: "local",
	}
	c.applyDefaults()
	return c
}

// Load reads the config from path. When path is empty it tries
// ./opsgate.yaml then ~/.opsgate/config.yaml, falling back to Default.
func Load(path string) (*Config, error) {
	if path == "" {
		for _, cand := range []string{"opsgate.yaml", expandHome("~/.opsgate/config.yaml")} {
			if _, err := os.Stat(cand); err == nil {
				path = cand
				break
			}
		}
	}
	if path == "" {
		return Default(), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Mode == "" {
		c.Mode = ModeObserve
	}
	if c.DefaultHost == "" {
		c.DefaultHost = "local"
	}
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = 30
	}
	if c.MaxOutputBytes <= 0 {
		c.MaxOutputBytes = 48 * 1024
	}
	if c.Audit.Path == "" {
		c.Audit.Path = expandHome("~/.opsgate/audit.jsonl")
	} else {
		c.Audit.Path = expandHome(c.Audit.Path)
	}
	if len(c.Audit.RedactKeys) == 0 {
		c.Audit.RedactKeys = []string{"password", "passwd", "token", "secret", "apikey", "api_key", "key"}
	}
	if c.Files.MaxBytes <= 0 {
		c.Files.MaxBytes = 64 * 1024
	}
	if len(c.Files.AllowPaths) == 0 {
		c.Files.AllowPaths = []string{"/var/log", "/etc/nginx", "/etc/systemd"}
	}
	if c.Tools == nil {
		c.Tools = map[string]ToolRule{}
	}
}

func (c *Config) validate() error {
	switch c.Mode {
	case ModeObserve, ModeOperate, ModeFull:
	default:
		return fmt.Errorf("invalid mode %q (want observe|operate|full)", c.Mode)
	}
	for name, h := range c.Hosts {
		if name == "local" {
			return fmt.Errorf("host name %q is reserved for the local machine", name)
		}
		if h.Addr == "" {
			return fmt.Errorf("host %q: addr is required", name)
		}
		if h.Mode != "" && h.Mode != ModeObserve && h.Mode != ModeOperate && h.Mode != ModeFull {
			return fmt.Errorf("host %q: invalid mode %q", name, h.Mode)
		}
	}
	if c.DefaultHost != "local" {
		if _, ok := c.Hosts[c.DefaultHost]; !ok {
			return fmt.Errorf("default_host %q is not defined under hosts", c.DefaultHost)
		}
	}
	return nil
}

// HostMode returns the effective mode for a host.
func (c *Config) HostMode(host string) Mode {
	if h, ok := c.Hosts[host]; ok && h.Mode != "" {
		return h.Mode
	}
	return c.Mode
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
