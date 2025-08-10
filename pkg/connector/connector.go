package connector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/ptr"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/commands"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"github.com/iFixRobots/emaildawg/pkg/imap"
	"github.com/iFixRobots/emaildawg/pkg/matrix"
	"github.com/iFixRobots/emaildawg/pkg/email"
	"github.com/iFixRobots/emaildawg/pkg/common"
)

type EmailConnector struct {
	Bridge        *bridgev2.Bridge
	Config        Config
	IMAPManager   *imap.Manager
	RoomManager   *matrix.RoomManager
	ThreadManager *email.ThreadManager
	Processor     *email.Processor
	DB            *EmailAccountQuery
}

var (
	_ bridgev2.NetworkConnector = (*EmailConnector)(nil)
	_ bridgev2.StoppableNetwork = (*EmailConnector)(nil)
	// Global connector instance for command access
	ConnectorInstance *EmailConnector
)

func (ec *EmailConnector) GetName() bridgev2.BridgeName {
	return bridgev2.BridgeName{
		DisplayName:          "EmailDawg",
		NetworkURL:           "https://en.wikipedia.org/wiki/Email",
		NetworkIcon:          "mxc://maunium.net/YgtkucQxWlKJxwMBJR6Ggz5w", // Email icon
		NetworkID:            "email",
		BeeperBridgeType:     "email",
		DefaultPort:          29319, // Different from WhatsApp's 29318
		DefaultCommandPrefix: "!email",
	}
}

func (ec *EmailConnector) Init(bridge *bridgev2.Bridge) {
	ec.Bridge = bridge
	
	// Initialize config with default values
	ec.Config = Config{
		Network: NetworkConfig{
			IMAP: IMAPConfig{
				DefaultTimeout:            30,
				StartupBackfillSeconds:    180,
				StartupBackfillMax:        25,
				InitialIdleTimeoutSeconds: 3,
			},
		},
		Logging: LoggingConfig{
			Sanitized:       true,
			PseudonymSecret: "",
		},
		Processing: ProcessingConfig{
			MaxUploadBytes:  10 * 1024 * 1024,
			GzipLargeBodies: true,
		},
	}

	// Allow environment overrides for verbose logging
	// EMAILDAWG_LOG_LEVEL: trace|debug|info|warn|error
	if lvl := strings.ToLower(os.Getenv("EMAILDAWG_LOG_LEVEL")); lvl != "" {
		switch lvl {
		case "trace":
			zerolog.SetGlobalLevel(zerolog.TraceLevel)
		case "debug":
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		case "info":
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
		case "warn":
			zerolog.SetGlobalLevel(zerolog.WarnLevel)
		case "error":
			zerolog.SetGlobalLevel(zerolog.ErrorLevel)
		}
	} else {
		// Default to maximum verbosity for analysis
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	}
	if san := strings.ToLower(os.Getenv("EMAILDAWG_LOG_SANITIZED")); san == "false" || san == "0" || san == "no" {
		ec.Config.Logging.Sanitized = false
	}

	// Set global instance for command access
	ConnectorInstance = ec
	
	// Ensure ./data directory exists for local SQLite files and sidecar WAL/SHM files
	dataDir := filepath.Join(".", "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		bridge.Log.Warn().Err(err).Str("path", dataDir).Msg("Failed to ensure data directory exists")
	}
	if wd, err := os.Getwd(); err == nil {
		bridge.Log.Info().Str("cwd", wd).Str("data_dir", dataDir).Msg("Startup environment")
	}

	// Initialize database
	ec.DB = &EmailAccountQuery{
		DB: bridge.DB,
	}
	
	// Create database tables
	ctx := context.Background()
	if err := ec.DB.CreateTable(ctx); err != nil {
		bridge.Log.Fatal().Err(err).Msg("Failed to create email_accounts table")
	}
	// Database health check: ensure we can write to the DB directory to avoid runtime I/O errors
	if err := ec.checkDBWritable(ctx); err != nil {
		bridge.Log.Fatal().Err(err).Msg("Database is not writable. Fix filesystem permissions or remove stale DB files, then restart the bridge.")
	}
	// Best-effort: add index for faster message lookups by (network, remote_id) if schema matches.
	if _, err := bridge.DB.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_message_network_remote ON message(network, remote_id)`); err == nil {
		bridge.Log.Trace().Msg("Ensured index idx_message_network_remote on message(network, remote_id)")
	}
	if _, err := bridge.DB.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_messages_network_remote ON messages(network, remote_id)`); err == nil {
		bridge.Log.Trace().Msg("Ensured index idx_messages_network_remote on messages(network, remote_id)")
	}

	// Initialize managers
	logger := bridge.Log.With().Str("component", "imap").Logger()
	ec.IMAPManager = imap.NewManager(bridge, &logger, ec.Config.Logging.Sanitized, ec.Config.Logging.PseudonymSecret)
	
	roomLogger := bridge.Log.With().Str("component", "matrix").Logger()
	ec.RoomManager = matrix.NewRoomManager(&roomLogger)
	
	// Prefer a DB-backed resolver that can find existing portals by prior bridged messages
	resolver := &DBThreadMetadataResolver{Bridge: bridge, Log: &roomLogger, Network: "email"}
	ec.ThreadManager = email.NewThreadManager(resolver)
	
	// Initialize email processor and wire it to the IMAP manager
	processorLogger := bridge.Log.With().Str("component", "email_processor").Logger()
	ec.Processor = email.NewProcessor(&processorLogger, ec.ThreadManager, ec.Config.Logging.Sanitized, ec.Config.Logging.PseudonymSecret)
	// Apply processing config
	if ec.Config.Processing.MaxUploadBytes > 0 {
		ec.Processor.MaxUploadBytes = ec.Config.Processing.MaxUploadBytes
	}
	ec.Processor.GzipLargeBodies = ec.Config.Processing.GzipLargeBodies
	ec.IMAPManager.SetProcessor(ec.Processor)
	
	// Add commands
	ec.Bridge.Commands.(*commands.Processor).AddHandlers(
		CommandPing,
		CommandStatus,
		CommandLogin,
		CommandLogout,
		CommandList,
		CommandSync,
		CommandReconnect,
		CommandNuke,
	)
}

func (ec *EmailConnector) Start(ctx context.Context) error {
	ec.Bridge.Log.Info().Msg("Email connector starting...")
	return nil
}

// Stop gracefully shuts down the EmailConnector and all IMAP connections
func (ec *EmailConnector) Stop() {
	ec.Bridge.Log.Info().Msg("Email connector stopping...")
	
	// Stop all IMAP clients
	if ec.IMAPManager != nil {
		ec.IMAPManager.StopAll()
	}
	
	// Clear global instance
	ConnectorInstance = nil
	
	ec.Bridge.Log.Info().Msg("Email connector stopped")
}

// LoadUserLogin is now implemented in client.go

func (ec *EmailConnector) GetCapabilities() *bridgev2.NetworkGeneralCapabilities {
	return &bridgev2.NetworkGeneralCapabilities{
		DisappearingMessages: false,
		AggressiveUpdateInfo: false,
	}
}

func (ec *EmailConnector) GetUserInfo(ctx context.Context, ghost *bridgev2.Ghost) (*bridgev2.UserInfo, error) {
	// Extract email address from ghost ID
	userIDStr := string(ghost.ID)
	// Remove "email:" prefix if present
	if len(userIDStr) > 6 && userIDStr[:6] == "email:" {
		userIDStr = userIDStr[6:]
	}
	return &bridgev2.UserInfo{
		Name:      &userIDStr,
		Avatar:    nil,
		IsBot:     nil,
		Identifiers: []string{userIDStr},
	}, nil
}

// GetChatInfo implements the bridgev2 interface for portal/room creation
func (ec *EmailConnector) GetChatInfo(ctx context.Context, portal *bridgev2.Portal, userLogin *bridgev2.UserLogin, portalID networkid.PortalKey) (*bridgev2.ChatInfo, error) {
	// Extract thread ID from portal ID
	threadID := string(portalID.ID)
	if len(threadID) > 7 && threadID[:7] == "thread:" {
		threadID = threadID[7:] // Remove "thread:" prefix
	}

	// If we have richer thread info, build the room using RoomManager
	if ec.ThreadManager != nil && ec.RoomManager != nil {
		if thread := ec.ThreadManager.GetThreadByID(string(userLogin.ID), threadID); thread != nil {
			return ec.RoomManager.GetChatInfoForThread(ctx, thread, userLogin)
		}
	}

	// Fallback: basic room configuration when thread is not yet known
	roomName := fmt.Sprintf("Email Thread: %s", threadID)
	roomTopic := "Email thread - messages will appear here when emails are received"

	// Start with empty member list - participants will be added when emails are processed
	chatMembers := make([]bridgev2.ChatMember, 0)
	
	chatInfo := &bridgev2.ChatInfo{
		Name:   &roomName,
		Topic:  &roomTopic,
		Avatar: nil,
		Type:  ptr.Ptr(database.RoomTypeDefault),
		Members: &bridgev2.ChatMemberList{
			Members: chatMembers,
			IsFull:  true,
		},
	}

	ec.Bridge.Log.Debug().
		Str("thread_id", threadID).
		Str("room_name", roomName).
		Msg("Created fallback ChatInfo for email thread")

	return chatInfo, nil
}

// Required methods for NetworkConnector interface
func (ec *EmailConnector) CreateLogin(ctx context.Context, user *bridgev2.User, flowID string) (bridgev2.LoginProcess, error) {
	return &EmailLoginProcess{user: user}, nil
}

func (ec *EmailConnector) GetDBMetaTables() []any {
	return []any{
		&EmailAccount{},
	}
}

func (ec *EmailConnector) GetDBMetaTypes() database.MetaTypes {
	return database.MetaTypes{}
}


func (ec *EmailConnector) GetBridgeInfoVersion() (int, int) {
	return 0, 1 // Version 0.1
}

func (ec *EmailConnector) GetLoginFlows() []bridgev2.LoginFlow {
	return []bridgev2.LoginFlow{{
		Name:        "email-password",
		Description: "Email and password login",
		ID:          "email-password",
	}}
}


// Helper functions for creating network IDs
func MakeUserID(email string) networkid.UserID {
	return common.EmailToGhostID(email)
}

func MakePortalID(threadID string) networkid.PortalID {
	return networkid.PortalID(fmt.Sprintf("thread:%s", threadID))
}

// checkDBWritable attempts a few write operations to ensure the underlying DB is writable
// and the directory allows journaling/WAL files. This prevents silent runtime failures later.
func (ec *EmailConnector) checkDBWritable(ctx context.Context) error {
	// Create a tiny health table and write a row, then delete it.
	_, err := ec.Bridge.DB.Exec(ctx, `CREATE TABLE IF NOT EXISTS email_health_check (ts INTEGER NOT NULL)`)
	if err != nil {
		return fmt.Errorf("failed to create health check table: %w", err)
	}
	_, err = ec.Bridge.DB.Exec(ctx, `INSERT INTO email_health_check (ts) VALUES (?)`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("failed to insert into health check table: %w", err)
	}
	_, err = ec.Bridge.DB.Exec(ctx, `DELETE FROM email_health_check`)
	if err != nil {
		return fmt.Errorf("failed to delete from health check table: %w", err)
	}
	return nil
}
