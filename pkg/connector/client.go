package connector

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/status"
	"maunium.net/go/mautrix/event"

	"github.com/iFixRobots/emaildawg/pkg/imap"
)

// EmailClient implements bridgev2.NetworkAPI for email accounts
type EmailClient struct {
	Main      *EmailConnector
	UserLogin *bridgev2.UserLogin

	// Email account information
	Email    string
	Username string
	Password string

	// IMAP client
	IMAPClient *imap.Client

	// State management
	isConnected atomic.Bool
	stopLoops   atomic.Pointer[context.CancelFunc]

	// Synchronization
	historySyncMutex sync.Mutex
	lastSyncTime     time.Time

	// Background processing
}

var (
	_ bridgev2.NetworkAPI = (*EmailClient)(nil)
)

// EmailClientErrors
var (
	EmailNotLoggedIn      = status.BridgeStateErrorCode("E-EMAIL-001")
	EmailConnectionFailed = status.BridgeStateErrorCode("E-EMAIL-002")
)

func (ec *EmailConnector) LoadUserLogin(ctx context.Context, login *bridgev2.UserLogin) error {
	// Create email client for this login
	emailClient := &EmailClient{
		Main:      ec,
		UserLogin: login,
	}
	login.Client = emailClient

	// Extract login metadata with proper error handling
	var email, username string
	if login.Metadata != nil {
		if loginMetadata, ok := login.Metadata.(*EmailLoginMetadata); ok && loginMetadata.Email != "" {
			email = loginMetadata.Email
			username = loginMetadata.Username
			ec.Bridge.Log.Debug().Str("email", email).Msg("Loaded credentials from login metadata")
		}
	}

	// If metadata is missing or invalid, try to extract email from login ID
	if email == "" {
		// Login ID format should be "email:user@domain.com"
		loginIDStr := string(login.ID)
		if len(loginIDStr) > 6 && loginIDStr[:6] == "email:" {
			email = loginIDStr[6:]
			username = email // Use email as username by default
			ec.Bridge.Log.Debug().Str("email", email).Msg("Extracted email from login ID")
		}
	}

	// If we still don't have an email, this login is invalid
	if email == "" {
		ec.Bridge.Log.Warn().Str("login_id", string(login.ID)).Msg("No email found in login metadata or ID")
		return nil
	}

	emailClient.Email = email
	emailClient.Username = username

	// Load account credentials from database
	account, err := ec.DB.GetAccount(ctx, login.UserMXID.String(), emailClient.Email)
	if err != nil {
		return fmt.Errorf("failed to load email account: %w", err)
	}

	if account == nil {
		ec.Bridge.Log.Debug().Str("email", emailClient.Email).Msg("No account credentials found")
		return nil
	}

	emailClient.Password = account.Password

	// Create IMAP client
	logger := login.Log.With().Str("component", "imap").Logger()
	emailClient.IMAPClient, err = imap.NewClient(
		emailClient.Email,
		emailClient.Username,
		emailClient.Password,
		login,
		&logger,
		ec.Config.Logging.Sanitized,
		ec.Config.Logging.PseudonymSecret,
		ec.Config.Network.IMAP.StartupBackfillSeconds,
		ec.Config.Network.IMAP.StartupBackfillMax,
		ec.Config.Network.IMAP.InitialIdleTimeoutSeconds,
	)
	if err != nil {
		return fmt.Errorf("failed to create IMAP client: %w", err)
	}

	// Set the email processor on the IMAP client
	if ec.Processor != nil {
		emailClient.IMAPClient.SetProcessor(ec.Processor)
	}

	// Automatically connect the client after loading
	go emailClient.Connect(ctx)

	// Register client with IMAP manager for status reporting
	go func() {
		// Wait a moment for connection to establish
		time.Sleep(2 * time.Second)
		if emailClient.IsConnected() {
			// Register the connected client with the manager for status reporting
			ec.IMAPManager.RegisterClient(login.UserMXID.String(), emailClient.Email, emailClient.IMAPClient)
		}
	}()

	return nil
}

func (ec *EmailClient) Connect(ctx context.Context) {
	if ec.IMAPClient == nil {
		state := status.BridgeState{
			StateEvent: status.BridgeStateEvent("BAD_CREDENTIALS"),
			Error:      EmailNotLoggedIn,
		}
		ec.UserLogin.BridgeState.Send(state)
		return
	}

	// Emit STARTING before beginning connection work
	ec.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.BridgeStateEvent("STARTING")})

	// Connect to IMAP server
	if err := ec.IMAPClient.Connect(); err != nil {
		ec.UserLogin.Log.Error().Err(err).Msg("Failed to connect to IMAP server")
		state := status.BridgeState{
			StateEvent: status.BridgeStateEvent("BRIDGE_UNREACHABLE"),
			Error:      EmailConnectionFailed,
			Info: map[string]any{
				"go_error": err.Error(),
			},
		}
		ec.UserLogin.BridgeState.Send(state)
		return
	}

	// We’re connected to the server; emit RUNNING (service up but not yet fully ready)
	ec.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.BridgeStateEvent("RUNNING")})

	ec.isConnected.Store(true)

	// Start IMAP IDLE monitoring with retry logic (includes baseline/backfill)
	if err := ec.startIDLEWithRetry(); err != nil {
		ec.UserLogin.Log.Error().Err(err).Msg("Failed to start IMAP IDLE after retries")
		// Set bridge state to indicate IDLE failure and do NOT mark as connected
		state := status.BridgeState{
			StateEvent: status.BridgeStateEvent("TRANSIENT_DISCONNECT"),
			Error:      EmailConnectionFailed,
			Info: map[string]any{
				"go_error":   err.Error(),
				"error_type": "IDLE_startup_failed",
			},
		}
		ec.UserLogin.BridgeState.Send(state)
		return
	}

	// Start background loops now that IDLE is running and baseline/backfill are done
	ec.startLoops()

	// Send connected state only after readiness is complete
	state := status.BridgeState{StateEvent: status.BridgeStateEvent("CONNECTED")}
	ec.UserLogin.BridgeState.Send(state)

	ec.UserLogin.Log.Info().Msg("Email client connected successfully and ready (baseline/backfill complete)")
}

func (ec *EmailClient) Disconnect() {
	ec.isConnected.Store(false)

	// Stop background loops
	if cancel := ec.stopLoops.Swap(nil); cancel != nil {
		(*cancel)()
	}

	// Stop IMAP monitoring and disconnect
	if ec.IMAPClient != nil {
		ec.IMAPClient.StopIDLE()
		ec.IMAPClient.Disconnect()
	}

	ec.UserLogin.Log.Info().Msg("Email client disconnected")
}

func (ec *EmailClient) LogoutRemote(ctx context.Context) {
	ec.UserLogin.Log.Info().Msg("Logging out from email account")

	// Remove account from database
	if err := ec.Main.DB.DeleteAccount(ctx, ec.UserLogin.UserMXID.String(), ec.Email); err != nil {
		ec.UserLogin.Log.Error().Err(err).Msg("Failed to delete account from database")
	}

	// Disconnect gracefully
	ec.Disconnect()

	// Remove from IMAP manager
	if err := ec.Main.IMAPManager.RemoveAccount(ec.UserLogin.UserMXID.String(), ec.Email); err != nil {
		ec.UserLogin.Log.Error().Err(err).Msg("Failed to remove account from IMAP manager")
	}

	// Clear credentials
	ec.Password = ""
	ec.IMAPClient = nil

	// CRITICAL: Delete the UserLogin record from bridgev2 database
	// This is what actually removes the login from the bridge framework
	logoutState := status.BridgeState{
		StateEvent: status.StateLoggedOut,
		Source:     "bridge",
	}
	ec.UserLogin.Delete(ctx, logoutState, bridgev2.DeleteOpts{})
	ec.UserLogin.Log.Debug().Msg("Successfully deleted UserLogin from bridge database")

	ec.UserLogin.Log.Info().Msg("Successfully logged out from email account")
}

func (ec *EmailClient) IsLoggedIn() bool {
	return ec.IMAPClient != nil && ec.isConnected.Load()
}

func (ec *EmailClient) IsConnected() bool {
	return ec.isConnected.Load()
}

// Stop gracefully stops all client operations and cleans up resources
func (ec *EmailClient) Stop(ctx context.Context) {
	ec.UserLogin.Log.Info().Msg("Stopping email client")

	// Mark as disconnected first to prevent new items being queued
	ec.isConnected.Store(false)

	// Stop all background loops
	if cancel := ec.stopLoops.Swap(nil); cancel != nil {
		(*cancel)()
		// Give goroutines time to exit cleanly
		time.Sleep(100 * time.Millisecond)
	}

	// Disconnect from IMAP server
	if ec.IMAPClient != nil {
		ec.IMAPClient.StopIDLE()
		ec.IMAPClient.Disconnect()
	}

	ec.UserLogin.Log.Info().Msg("Email client stopped")
}

// startIDLEWithRetry attempts to start IDLE with ONE connection reset if needed
func (ec *EmailClient) startIDLEWithRetry() error {
	// First, test connection health with a NOOP command
	if err := ec.IMAPClient.TestConnection(); err != nil {
		ec.UserLogin.Log.Warn().Err(err).Msg("Connection test failed, forcing reconnection")
		if err := ec.reconnectIMAPClient(); err != nil {
			return fmt.Errorf("failed to reconnect after connection test failure: %w", err)
		}
	}

	// Try to start IDLE (first attempt)
	if err := ec.IMAPClient.StartIDLE(); err != nil {
		// Check if it's the "IDLE already running" error
		if strings.Contains(err.Error(), "IDLE already") || strings.Contains(err.Error(), "already running") {
			ec.UserLogin.Log.Warn().Err(err).Msg("Server reports IDLE already running - attempting ONE reconnection")

			// Force reconnection to clear server-side state (ONLY ONCE)
			if err := ec.reconnectIMAPClient(); err != nil {
				return fmt.Errorf("failed to reconnect after IDLE conflict: %w", err)
			}

			// Try IDLE again on fresh connection (FINAL ATTEMPT)
			if err := ec.IMAPClient.StartIDLE(); err != nil {
				// If it still fails, give up - don't loop forever
				ec.UserLogin.Log.Error().Err(err).Msg("IDLE failed even after reconnection - giving up to prevent connection loop")
				return fmt.Errorf("IDLE startup failed: %w", err)
			}

			ec.UserLogin.Log.Info().Msg("Successfully started IDLE after connection reset")
			return nil
		}

		// Other IDLE error - don't retry
		return fmt.Errorf("IDLE startup failed: %w", err)
	}

	ec.UserLogin.Log.Info().Msg("IDLE started successfully")
	return nil
}

// reconnectIMAPClient performs a full disconnect and reconnect
func (ec *EmailClient) reconnectIMAPClient() error {
	ec.UserLogin.Log.Info().Msg("Reconnecting IMAP client to clear server-side state")

	// Stop IDLE first if it's running
	if ec.IMAPClient != nil {
		ec.IMAPClient.StopIDLE()
		ec.IMAPClient.Disconnect()
	}

	// Wait for server-side cleanup
	time.Sleep(2 * time.Second)

	// Reconnect
	if err := ec.IMAPClient.Connect(); err != nil {
		return fmt.Errorf("failed to reconnect IMAP: %w", err)
	}

	ec.UserLogin.Log.Info().Msg("IMAP reconnection successful")
	return nil
}

func (ec *EmailClient) startLoops() {
	ctx, cancel := context.WithCancel(context.Background())
	ec.stopLoops.Store(&cancel)

	// Start periodic sync checker
	go ec.periodicSyncLoop(ctx)
}

func (ec *EmailClient) periodicSyncLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ec.performPeriodicSync(ctx)
		}
	}
}

func (ec *EmailClient) performPeriodicSync(ctx context.Context) {
	// Keep ctx parameter used to satisfy linters even if not currently leveraged here.
	_ = ctx
	ec.historySyncMutex.Lock()
	defer ec.historySyncMutex.Unlock()

	// Check if we need to perform a sync
	if time.Since(ec.lastSyncTime) < time.Minute {
		ec.UserLogin.Log.Debug().Msg("[PERIODIC SYNC] Skipping sync - too soon since last sync")
		return
	}

	ec.UserLogin.Log.Debug().Msg("[PERIODIC SYNC] Starting periodic sync")

	// Trigger IMAP to check for new messages (in case IDLE missed something)
	if ec.IMAPClient != nil && ec.IMAPClient.IsConnected() {
		if ec.IMAPClient.IsIDLERunning() {
			ec.UserLogin.Log.Debug().Msg("[PERIODIC SYNC] IDLE is running - triggering manual check (will interrupt IDLE)")
		} else {
			ec.UserLogin.Log.Debug().Msg("[PERIODIC SYNC] IDLE not running - safe to check messages")
		}

		if err := ec.IMAPClient.CheckNewMessages(); err != nil {
			ec.UserLogin.Log.Warn().Err(err).Msg("[PERIODIC SYNC] Failed to check for new messages during periodic sync")
		} else {
			ec.UserLogin.Log.Debug().Msg("[PERIODIC SYNC] Message check completed successfully")
		}
	} else {
		ec.UserLogin.Log.Warn().Msg("[PERIODIC SYNC] IMAP client not available or not connected")
	}

	// Update sync time
	ec.lastSyncTime = time.Now()

	ec.UserLogin.Log.Debug().Msg("[PERIODIC SYNC] Periodic sync completed")
}

// GetCapabilities returns the capabilities of this network
func (ec *EmailClient) GetCapabilities(ctx context.Context, portal *bridgev2.Portal) *event.RoomFeatures {
	// Must return a non-nil RoomFeatures or mautrix will panic when calling GetID.
	// Email threads are simple and read-only, so use default features.
	return &event.RoomFeatures{}
}

func (ec *EmailClient) IsThisUser(ctx context.Context, userID networkid.UserID) bool {
	// Check if this user ID corresponds to our email account
	expectedUserID := MakeUserID(ec.Email)
	return userID == expectedUserID
}

// GetChatInfo implements the NetworkAPI interface - delegates to connector
func (ec *EmailClient) GetChatInfo(ctx context.Context, portal *bridgev2.Portal) (*bridgev2.ChatInfo, error) {
	return ec.Main.GetChatInfo(ctx, portal, ec.UserLogin, networkid.PortalKey{ID: portal.ID})
}

// GetUserInfo implements the NetworkAPI interface - delegates to connector
func (ec *EmailClient) GetUserInfo(ctx context.Context, ghost *bridgev2.Ghost) (*bridgev2.UserInfo, error) {
	return ec.Main.GetUserInfo(ctx, ghost)
}

// HandleMatrixMessage implements the NetworkAPI interface
func (ec *EmailClient) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (*bridgev2.MatrixMessageResponse, error) {
	// For now, email is read-only from Matrix side
	ec.UserLogin.Log.Warn().Msg("Received Matrix message for read-only email portal")
	return &bridgev2.MatrixMessageResponse{
		DB: nil, // No database message entry needed for rejected message
	}, nil
}
