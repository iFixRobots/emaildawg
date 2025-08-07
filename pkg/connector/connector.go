package connector

import (
	"context"
	"fmt"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/commands"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"go.mau.fi/mautrix-emaildawg/pkg/imap"
	"go.mau.fi/mautrix-emaildawg/pkg/matrix"
	"go.mau.fi/mautrix-emaildawg/pkg/email"
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
		DisplayName:          "Email",
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
		IMAP: IMAPConfig{
			DefaultTimeout: 30,
		},
	}
	
	// Set global instance for command access
	ConnectorInstance = ec
	
	// Initialize database
	ec.DB = &EmailAccountQuery{
		DB: bridge.DB,
	}
	
	// Create database tables
	ctx := context.Background()
	if err := ec.DB.CreateTable(ctx); err != nil {
		bridge.Log.Fatal().Err(err).Msg("Failed to create email_accounts table")
	}
	
	// Initialize managers
	logger := bridge.Log.With().Str("component", "imap").Logger()
	ec.IMAPManager = imap.NewManager(*bridge, &logger)
	
	roomLogger := bridge.Log.With().Str("component", "matrix").Logger()
	ec.RoomManager = matrix.NewRoomManager(&roomLogger)
	
	ec.ThreadManager = email.NewThreadManager()
	
	// Initialize email processor and wire it to the IMAP manager
	processorLogger := bridge.Log.With().Str("component", "email_processor").Logger()
	ec.Processor = email.NewProcessor(&processorLogger, ec.ThreadManager)
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

	// Create basic room configuration
	// Room details will be updated when actual emails are processed
	roomName := fmt.Sprintf("Email Thread: %s", threadID)
	roomTopic := "Email thread - messages will appear here when emails are received"

	// Start with empty member list - participants will be added when emails are processed
	chatMembers := make([]bridgev2.ChatMember, 0)
	
	chatInfo := &bridgev2.ChatInfo{
		Name:   &roomName,
		Topic:  &roomTopic,
		Avatar: nil, // Could add email provider icons in the future
		
		// Default room type for email threads
		Type: nil,
		
		// Participants will be added dynamically as emails are processed
		Members: &bridgev2.ChatMemberList{
			Members: chatMembers,
			IsFull:  true,
		},
	}

	ec.Bridge.Log.Debug().
		Str("thread_id", threadID).
		Str("room_name", roomName).
		Msg("Created ChatInfo for email thread")

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
	return networkid.UserID(fmt.Sprintf("email:%s", email))
}

func MakePortalID(threadID string) networkid.PortalID {
	return networkid.PortalID(fmt.Sprintf("thread:%s", threadID))
}
