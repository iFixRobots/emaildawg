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

	"github.com/iFixRobots/emaildawg/pkg/coordinator"
	"github.com/iFixRobots/emaildawg/pkg/imap"
	"github.com/iFixRobots/emaildawg/pkg/reliability"
)

// ClientConfig holds configuration for EmailClient timing and behavior
type ClientConfig struct {
	// Registration wait time before checking if client connected
	RegistrationWaitTime time.Duration

	// Reconnection sleep time to allow server-side cleanup
	ReconnectionSleepTime time.Duration

	// Periodic sync interval
	PeriodicSyncInterval time.Duration

	// Minimum time between sync operations (throttling)
	SyncThrottleTime time.Duration
}

// DefaultClientConfig returns sensible defaults for client configuration
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		RegistrationWaitTime:  2 * time.Second,
		ReconnectionSleepTime: 2 * time.Second,
		PeriodicSyncInterval:  5 * time.Minute,
		SyncThrottleTime:      time.Minute,
	}
}

// EmailClient implements bridgev2.NetworkAPI for email accounts
type EmailClient struct {
	Main      *EmailConnector
	UserLogin *bridgev2.UserLogin

	// Email account information
	Email    string
	Username string
	Password string

	// Folders to monitor (from user selection during login)
	MonitoredFolders []string

	// IMAP client
	IMAPClient *imap.Client

	// Configuration
	config ClientConfig

	// State management
	stateCoordinator *coordinator.StateCoordinator
	isConnected      atomic.Bool
	stopLoops        atomic.Pointer[context.CancelFunc]

	// Client lifecycle context management
	ctx    context.Context
	cancel context.CancelFunc

	// Synchronization
	historySyncMutex sync.Mutex
	lastSyncTime     time.Time
}

var (
	_ bridgev2.NetworkAPI = (*EmailClient)(nil)
)

// EmailClientErrors - Core connector-level errors
var (
	EmailNotLoggedIn      = status.BridgeStateErrorCode("E-EMAIL-001")
	EmailConnectionFailed = status.BridgeStateErrorCode("E-EMAIL-002")
	EmailAuthFailure      = status.BridgeStateErrorCode("E-EMAIL-005")
)

// extractEmailCredentials extracts email and username from login metadata or login ID
func (ec *EmailConnector) extractEmailCredentials(login *bridgev2.UserLogin) (string, string, error) {
	var email, username string

	// Extract login metadata with proper error handling
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
		return "", "", fmt.Errorf("invalid login: no email found in metadata or login ID %s", login.ID)
	}

	return email, username, nil
}

// loadAccountCredentials loads account credentials from database
func (ec *EmailConnector) loadAccountCredentials(ctx context.Context, userMXID, email string) (*EmailAccount, error) {
	account, err := ec.DB.GetAccount(ctx, userMXID, email)
	if err != nil {
		return nil, fmt.Errorf("failed to load email account: %w", err)
	}

	if account == nil {
		ec.Bridge.Log.Debug().Str("email", email).Msg("No account credentials found")
		return nil, fmt.Errorf("no account credentials found for email %s", email)
	}

	return account, nil
}

// createIMAPClient creates and configures the IMAP client
func (ec *EmailConnector) createIMAPClient(emailClient *EmailClient, login *bridgev2.UserLogin) error {
	logger := login.Log.With().Str("component", "imap").Logger()
	imapClient, err := imap.NewClient(
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
		emailClient.stateCoordinator,
	)
	if err != nil {
		return fmt.Errorf("failed to create IMAP client: %w", err)
	}

	emailClient.IMAPClient = imapClient

	// Set the email processor on the IMAP client
	if ec.Processor != nil {
		emailClient.IMAPClient.SetProcessor(ec.Processor)
	}

	return nil
}

// startClientConnections starts the client connection and registration processes
func (ec *EmailConnector) startClientConnections(emailClient *EmailClient, login *bridgev2.UserLogin) {
	// Automatically connect the client after loading
	// Use client's lifecycle context for long-running connection
	go emailClient.Connect(emailClient.ctx)

	// Register client with IMAP manager for status reporting
	go func() {
		// Wait a moment for connection to establish, respecting context cancellation
		select {
		case <-time.After(emailClient.config.RegistrationWaitTime):
			if emailClient.IsConnected() {
				// Register the connected client with the manager for status reporting
				ec.IMAPManager.RegisterClient(login.UserMXID.String(), emailClient.Email, emailClient.IMAPClient)
			}
		case <-emailClient.ctx.Done():
			// Client cancelled, exit goroutine
			return
		}
	}()
}

func (ec *EmailConnector) LoadUserLogin(ctx context.Context, login *bridgev2.UserLogin) error {
	// Create client lifecycle context that survives beyond this function
	clientCtx, clientCancel := context.WithCancel(context.Background())

	// Create email client for this login
	emailClient := &EmailClient{
		Main:      ec,
		UserLogin: login,
		ctx:       clientCtx,
		cancel:    clientCancel,
		config:    DefaultClientConfig(),
	}

	// Initialize state coordinator
	emailClient.stateCoordinator = coordinator.NewStateCoordinator(login, &ec.Bridge.Log)
	login.Client = emailClient

	// Extract email credentials
	email, username, err := ec.extractEmailCredentials(login)
	if err != nil {
		return err
	}
	emailClient.Email = email
	emailClient.Username = username

	// Load account credentials from database
	account, err := ec.loadAccountCredentials(ctx, login.UserMXID.String(), emailClient.Email)
	if err != nil {
		return err
	}
	emailClient.Password = account.Password
	emailClient.MonitoredFolders = account.MonitoredFolders

	// Log configured folders
	if len(account.MonitoredFolders) > 0 {
		ec.Bridge.Log.Info().
			Strs("folders", account.MonitoredFolders).
			Str("email", emailClient.Email).
			Msg("Loaded monitored folders configuration")
	} else {
		ec.Bridge.Log.Debug().Str("email", emailClient.Email).Msg("No monitored folders configured, will use INBOX")
		emailClient.MonitoredFolders = []string{"INBOX"}
	}

	// Create IMAP client
	if err := ec.createIMAPClient(emailClient, login); err != nil {
		return err
	}

	// Start client connections
	ec.startClientConnections(emailClient, login)

	return nil
}

func (ec *EmailClient) Connect(ctx context.Context) {
	if ec.IMAPClient == nil {
		ec.stateCoordinator.ReportSimpleEvent("inbox", "auth_failure", false, EmailNotLoggedIn, nil)
		return
	}

	// Emit STARTING before beginning connection work
	ec.stateCoordinator.ReportSimpleEvent("inbox", "connection_started", false, "", nil)

	// Connect to IMAP server
	if err := ec.IMAPClient.Connect(); err != nil {
		ec.UserLogin.Log.Error().Err(err).Msg("Failed to connect to IMAP server")
		ec.stateCoordinator.ReportSimpleEvent("inbox", "connection_lost", false, EmailConnectionFailed, map[string]any{"go_error": err.Error()})
		return
	}

	// We're connected to the server; emit RUNNING (service up but not yet fully ready)
	// Note: the actual connection_established event will be reported by the IMAP client

	// Start IMAP IDLE monitoring with retry logic (includes baseline/backfill)
	if err := ec.startIDLEWithRetry(); err != nil {
		ec.UserLogin.Log.Error().Err(err).Msg("Failed to start IMAP IDLE after retries")
		// Disconnect and reset state since IDLE failed
		ec.isConnected.Store(false)
		if ec.IMAPClient != nil {
			ec.IMAPClient.Disconnect()
		}
		// Report IDLE startup failure - this will be handled by the state coordinator
		ec.stateCoordinator.ReportSimpleEvent("inbox", string(coordinator.EventIdleFailed), false, imap.EmailIdleFailed, map[string]any{"go_error": err.Error(), "error_type": "IDLE_startup_failed"})
		return
	}

	// Only mark as connected after IDLE successfully starts
	ec.isConnected.Store(true)

	// Start background loops now that IDLE is running and baseline/backfill are done
	ec.startLoops()

	// Report successful IDLE startup - the coordinator will promote to CONNECTED
	ec.stateCoordinator.ReportSimpleEvent("inbox", "idle_started", true, "", nil)

	ec.UserLogin.Log.Info().Msg("Email client connected successfully and ready (baseline/backfill complete)")
}

func (ec *EmailClient) Disconnect() {
	ec.isConnected.Store(false)

	// Stop background loops
	if cancel := ec.stopLoops.Swap(nil); cancel != nil {
		(*cancel)()
	}

	// Stop IMAP monitoring and disconnect
	ec.disconnectIMAPClient()

	// Cancel client context to clean up any remaining goroutines
	if ec.cancel != nil {
		ec.cancel()
	}

	ec.UserLogin.Log.Info().Msg("Email client disconnected")
}

func (ec *EmailClient) LogoutRemote(ctx context.Context) {
	ec.UserLogin.Log.Info().Msg("Logging out from email account")

	// Remove account from database
	if err := ec.Main.DB.DeleteAccount(ctx, ec.UserLogin.UserMXID.String(), ec.Email); err != nil {
		ec.UserLogin.Log.Error().Err(err).Msg("Failed to delete account from database")
	}

	// Disconnect gracefully - this handles context cancellation and cleanup
	ec.Disconnect()

	// Remove from IMAP manager
	if err := ec.Main.IMAPManager.RemoveAccount(ec.UserLogin.UserMXID.String(), ec.Email); err != nil {
		ec.UserLogin.Log.Error().Err(err).Msg("Failed to remove account from IMAP manager")
	}

	// Clear credentials - safe after Disconnect() has cancelled all operations
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

// disconnectIMAPClient safely stops IDLE and disconnects the IMAP client
func (ec *EmailClient) disconnectIMAPClient() {
	if ec.IMAPClient != nil {
		ec.IMAPClient.StopIDLE()
		ec.IMAPClient.Disconnect()
	}
}

// Stop gracefully stops all client operations and cleans up resources
func (ec *EmailClient) Stop(ctx context.Context) {
	ec.UserLogin.Log.Info().Msg("Stopping email client")

	// Mark as disconnected first to prevent new items being queued
	ec.isConnected.Store(false)

	// Stop all background loops
	if cancel := ec.stopLoops.Swap(nil); cancel != nil {
		(*cancel)()
		// Background operations will terminate cleanly via context cancellation
	}

	// Disconnect from IMAP server
	ec.disconnectIMAPClient()

	// Cancel client context to clean up any remaining goroutines
	if ec.cancel != nil {
		ec.cancel()
	}

	ec.UserLogin.Log.Info().Msg("Email client stopped")
}

// startIDLEWithRetry attempts to start IDLE with robust retry logic and timeout protection
func (ec *EmailClient) startIDLEWithRetry() error {
	// Get IMAP timeout configuration for timeout protection
	timeoutConfig := reliability.IMAPTimeouts()

	// Add timeout for the entire IDLE startup sequence
	timeoutCtx, cancel := context.WithTimeout(ec.ctx, timeoutConfig.Command)
	defer cancel()

	return reliability.RetryWithBackoff(timeoutCtx, reliability.IDLEStartupRetryConfig(), func() error {
		// Test connection health first
		if err := ec.IMAPClient.TestConnection(); err != nil {
			ec.UserLogin.Log.Warn().Err(err).Msg("Connection test failed, will trigger reconnection via retry system")
			// Let the retry system handle connection recovery - this will trigger reconnectIMAPClient
			return err
		}

		// Attempt to start IDLE
		if err := ec.IMAPClient.StartIDLE(); err != nil {
			// Let the retry system categorize and decide whether to retry
			// This includes IDLE conflicts, server errors, and network issues
			ec.UserLogin.Log.Debug().Err(err).Msg("IDLE startup failed, letting retry system handle recovery")

			// For IDLE conflicts, force reconnection before next retry
			if strings.Contains(strings.ToLower(err.Error()), "idle already") ||
				strings.Contains(strings.ToLower(err.Error()), "already running") {
				if reconErr := ec.reconnectIMAPClient(); reconErr != nil {
					ec.UserLogin.Log.Warn().Err(reconErr).Msg("Failed to reconnect during IDLE conflict recovery")
					// Return original error, not reconnection error, for retry system categorization
				} else {
					ec.UserLogin.Log.Debug().Msg("Reconnected successfully to clear IDLE conflict")
				}
			}

			return err
		}

		ec.UserLogin.Log.Info().Msg("IDLE started successfully")
		return nil
	})
}

// reconnectIMAPClient performs a full disconnect and reconnect
func (ec *EmailClient) reconnectIMAPClient() error {
	ec.UserLogin.Log.Info().Msg("Reconnecting IMAP client to clear server-side state")

	// Stop IDLE first if it's running
	ec.disconnectIMAPClient()

	// Wait for server-side cleanup
	time.Sleep(ec.config.ReconnectionSleepTime)

	// Reconnect
	if err := ec.IMAPClient.Connect(); err != nil {
		return fmt.Errorf("failed to reconnect IMAP: %w", err)
	}

	ec.UserLogin.Log.Info().Msg("IMAP reconnection successful")
	return nil
}

func (ec *EmailClient) startLoops() {
	ctx, cancel := context.WithCancel(ec.ctx)
	ec.stopLoops.Store(&cancel)

	// Start periodic sync checker
	go ec.periodicSyncLoop(ctx)
}

func (ec *EmailClient) periodicSyncLoop(ctx context.Context) {
	ticker := time.NewTicker(ec.config.PeriodicSyncInterval)
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
	// Check if context is cancelled before proceeding
	select {
	case <-ctx.Done():
		ec.UserLogin.Log.Debug().Msg("[PERIODIC SYNC] Context cancelled, skipping sync")
		return
	default:
	}

	ec.historySyncMutex.Lock()
	defer ec.historySyncMutex.Unlock()

	// Check if we need to perform a sync
	if time.Since(ec.lastSyncTime) < ec.config.SyncThrottleTime {
		ec.UserLogin.Log.Debug().Msg("[PERIODIC SYNC] Skipping sync - too soon since last sync")
		return
	}

	ec.UserLogin.Log.Debug().Msg("[PERIODIC SYNC] Starting periodic sync")

	// Add timeout protection for periodic sync operations
	timeoutConfig := reliability.IMAPTimeouts()
	timeoutCtx, cancel := context.WithTimeout(ctx, timeoutConfig.Command)
	defer cancel()

	var err error
	func() {
		// Capture IMAP client reference safely to prevent nil pointer panic
		imapClient := ec.IMAPClient
		if imapClient != nil && imapClient.IsConnected() {
			if imapClient.IsIDLERunning() {
				ec.UserLogin.Log.Debug().Msg("[PERIODIC SYNC] IDLE is running - triggering manual check (will interrupt IDLE)")
			} else {
				ec.UserLogin.Log.Debug().Msg("[PERIODIC SYNC] IDLE not running - safe to check messages")
			}

			// Check if timeout context is cancelled
			select {
			case <-timeoutCtx.Done():
				err = timeoutCtx.Err()
				return
			default:
			}

			// Perform message check with timeout protection
			if syncErr := imapClient.CheckNewMessages(); syncErr != nil {
				err = fmt.Errorf("message check failed: %w", syncErr)
			} else {
				ec.UserLogin.Log.Debug().Msg("[PERIODIC SYNC] Message check completed successfully")
			}
		} else {
			ec.UserLogin.Log.Warn().Msg("[PERIODIC SYNC] IMAP client not available or not connected")
		}
	}()

	if err != nil {
		ec.UserLogin.Log.Warn().Err(err).Msg("[PERIODIC SYNC] Failed to check for new messages during periodic sync with timeout protection")
	}

	// Update sync time regardless of success/failure to maintain sync interval
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
	// Email bridge is designed as read-only - Matrix users can view emails but not send replies
	ec.UserLogin.Log.Warn().Msg("Received Matrix message for read-only email portal")
	return &bridgev2.MatrixMessageResponse{
		DB: nil, // No database message entry needed for rejected message
	}, nil
}
