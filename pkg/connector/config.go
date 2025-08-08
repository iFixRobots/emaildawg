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
	DefaultTimeout            int `yaml:"default_timeout"`
	StartupBackfillSeconds    int `yaml:"startup_backfill_seconds"`
	StartupBackfillMax        int `yaml:"startup_backfill_max"`
	InitialIdleTimeoutSeconds int `yaml:"initial_idle_timeout_seconds"`
}

type LoggingConfig struct {
	// When true, redact PII from logs using a global sanitizer hook.
	Sanitized        bool   `yaml:"sanitized"`
	PseudonymSecret  string `yaml:"pseudonym_secret"`
}

func upgradeConfig(helper up.Helper) {
	helper.Copy(up.Int, "imap", "default_timeout")
	helper.Copy(up.Int, "imap", "startup_backfill_seconds")
	helper.Copy(up.Int, "imap", "startup_backfill_max")
	helper.Copy(up.Int, "imap", "initial_idle_timeout_seconds")
	// These are optional and safe to ignore if not present
	helper.Copy(up.Bool, "logging", "sanitized")
}

func (ec *EmailConnector) GetConfig() (string, any, up.Upgrader) {
	return ExampleConfig, &ec.Config, &up.StructUpgrader{
		SimpleUpgrader: up.SimpleUpgrader(upgradeConfig),
		Blocks: [][]string{
			{"imap"},
		},
		Base: ExampleConfig,
	}
}
