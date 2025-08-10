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
// Default values are defined once below and applied at connector startup.
const DefaultMaxUploadBytes = 25 * 1024 * 1024 // 25 MiB

type ProcessingConfig struct {
	// Maximum size in bytes for a single media upload. Set 0 to disable the check.
	MaxUploadBytes int  `yaml:"max_upload_bytes"`
	// If true, attempt gzip for oversized original HTML/text bodies before attaching.
	GzipLargeBodies bool `yaml:"gzip_large_bodies"`
	// If true, send outbound messages from the user's email ghost by default.
	// If false, attempt to send as the user's Matrix account (double puppet) when available.
	PreferGhostOutbound bool `yaml:"prefer_ghost_outbound"`
}

func upgradeConfig(helper up.Helper) {
	// Only copy keys that exist in the embedded example (pkg/connector/example-config.yaml).
	// The embedded example currently only contains imap.default_timeout at the root level.
	helper.Copy(up.Int, "imap", "default_timeout")
}

func (ec *EmailConnector) GetConfig() (string, any, up.Upgrader) {
	return ExampleConfig, &ec.Config, &up.StructUpgrader{
		SimpleUpgrader: up.SimpleUpgrader(upgradeConfig),
		Blocks: [][]string{},
		Base: ExampleConfig,
	}
}
