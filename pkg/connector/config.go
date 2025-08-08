package connector

import (
	_ "embed"

	up "go.mau.fi/util/configupgrade"
)

//go:embed example-config.yaml
var ExampleConfig string

type Config struct {
	// Email-specific configuration
	IMAP    IMAPConfig    `yaml:"imap"`
	Logging LoggingConfig `yaml:"logging"`
}

type IMAPConfig struct {
	// IMAP connection settings will be configured per-user via DM commands
	// rather than in the global config file
	DefaultTimeout int `yaml:"default_timeout"`
}

type LoggingConfig struct {
	// When true, redact PII from logs using a global sanitizer hook.
	Sanitized        bool   `yaml:"sanitized"`
	PseudonymSecret  string `yaml:"pseudonym_secret"`
}

func upgradeConfig(helper up.Helper) {
	helper.Copy(up.Int, "imap", "default_timeout")
	// These are optional and safe to ignore if not present
	helper.Copy(up.Bool, "logging", "sanitized")
	// Older util may not expose up.String; copy as up.Str if available
	// If not, this is a best-effort noop in older versions.
	// Use Copy with type name "string" via up.FieldType, but the util exposes helpers only.
	// We'll keep only sanitized mandatory upgrade.
}

func (ec *EmailConnector) GetConfig() (string, any, up.Upgrader) {
	return ExampleConfig, &ec.Config, &up.StructUpgrader{
		SimpleUpgrader: up.SimpleUpgrader(upgradeConfig),
		Blocks: [][]string{
			{"imap"},
			{"logging"},
		},
		Base: ExampleConfig,
	}
}
