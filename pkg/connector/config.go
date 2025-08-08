package connector

import (
	_ "embed"

	up "go.mau.fi/util/configupgrade"
)

//go:embed example-config.yaml
var ExampleConfig string

type Config struct {
	// Top-level blocks to match example-config.yaml
	Network    NetworkConfig    `yaml:"network"`
	Logging    LoggingConfig    `yaml:"logging"`
	Processing ProcessingConfig `yaml:"email_processing"`
}

type NetworkConfig struct {
	IMAP IMAPConfig `yaml:"imap"`
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
	Sanitized       bool   `yaml:"sanitized"`
	PseudonymSecret string `yaml:"pseudonym_secret"`
}

// ProcessingConfig holds limits and behaviors for email → Matrix conversion
type ProcessingConfig struct {
	// Maximum size in bytes for a single media upload. Set 0 to disable the check.
	MaxUploadBytes int  `yaml:"max_upload_bytes"`
	// If true, attempt gzip for oversized original HTML/text bodies before attaching.
	GzipLargeBodies bool `yaml:"gzip_large_bodies"`
}

func upgradeConfig(helper up.Helper) {
	// network.imap.* keys
	helper.Copy(up.Int, "network", "imap", "default_timeout")
	helper.Copy(up.Int, "network", "imap", "startup_backfill_seconds")
	helper.Copy(up.Int, "network", "imap", "startup_backfill_max")
	helper.Copy(up.Int, "network", "imap", "initial_idle_timeout_seconds")
	// logging.* keys (optional)
	helper.Copy(up.Bool, "logging", "sanitized")
	// email_processing.* keys
	helper.Copy(up.Int, "email_processing", "max_upload_bytes")
	helper.Copy(up.Bool, "email_processing", "gzip_large_bodies")
}

func (ec *EmailConnector) GetConfig() (string, any, up.Upgrader) {
	return ExampleConfig, &ec.Config, &up.StructUpgrader{
		SimpleUpgrader: up.SimpleUpgrader(upgradeConfig),
		Blocks: [][]string{},
		Base: ExampleConfig,
	}
}
