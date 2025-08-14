package imap

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/status"

	"github.com/iFixRobots/emaildawg/pkg/email"
	logging "github.com/iFixRobots/emaildawg/pkg/logging"
)

// IMAPDebugWriter captures all IMAP protocol traffic for debugging
type IMAPDebugWriter struct {
	logger    *zerolog.Logger
	sanitized bool
}

// Write implements io.Writer to log IMAP protocol messages
func (w *IMAPDebugWriter) Write(p []byte) (n int, err error) {
	data := string(p)
	
	// Don't log credentials but log everything else
	if strings.Contains(strings.ToUpper(data), "LOGIN") {
		w.logger.Trace().Str("imap_data", "[LOGIN COMMAND - credentials redacted]").Msg("[IMAP PROTOCOL] Client -> Server")
	} else {
		if w.sanitized {
			// Summarize instead of dumping raw protocol contents
			w.logger.Trace().Str("imap_data", logging.SummarizeIMAPData(strings.TrimSpace(data))).Msg("[IMAP PROTOCOL] Data exchange")
		} else {
			w.logger.Trace().Str("imap_data", strings.TrimSpace(data)).Msg("[IMAP PROTOCOL] Data exchange")
		}
	}
	
	return len(p), nil
}

// Client manages IMAP synchronization for a specific email account.
// It establishes TWO independent IMAP TCP connections:
// - INBOX connection: runs an IDLE loop for real-time delivery (inbox-only).
// - Sent connection: runs a parallel IDLE loop on the Sent mailbox (outbound attribution).
// Both connections operate concurrently and never pause each other.
// Mailbox-aware processing ensures Sent items are attributed as from-me.
type Client struct {
	// Connection details
	Email    string
	Host     string
	Port     int
	Username string
	Password string
	TLS      bool

	// Logging/sanitization
	sanitized bool
	secret    string

	// INBOX IMAP client
	client     *imapclient.Client
	connected  bool
	idling     bool
	stopIdle   chan struct{}
	reconnect  chan struct{}
	
	// SENT IMAP client (second TCP connection)
	sentClient       *imapclient.Client
	sentConnected    bool
	sentIdling       bool // reserved for possible future IDLE on Sent
	sentStop         chan struct{}
	sentMu           sync.RWMutex
	sentFailureCount int
	sentLastFailure  time.Time
	
	// Startup behavior
	startupBackfillSeconds   int
	startupBackfillMax       int
	initialIdleTimeout       time.Duration
	idleInterval             time.Duration
	firstIdleCycle           bool

	// Mailbox management
	sentFolder string
	 
 	// Bridge integration
	login      *bridgev2.UserLogin // Can be nil for testing
	log        *zerolog.Logger
	processor  *email.Processor

	// Threading
	mu           sync.RWMutex
	lastInboxUID imap.UID
	lastSentUID  imap.UID
	// In-flight UID de-duplication per mailbox
	inFlightInbox map[imap.UID]struct{}
	inFlightSent  map[imap.UID]struct{}
	
	// Circuit breaker for connection failures
	failureCount int
	lastFailure  time.Time
	maxFailures  int
	backoffTime  time.Duration

	// Bridge state throttling
	lastStateEvent status.BridgeStateEvent
	lastStateError status.BridgeStateErrorCode
	lastStateTime  time.Time
	
	// Resource management
	ctx        context.Context
	cancel     context.CancelFunc
	isShutdown bool
	
	// Connection state tracking to prevent multiple connections
	connectingMu sync.Mutex
	isConnecting bool

	// Per-portal locks to serialize room creation
	portalLocks sync.Map // map[string]*sync.Mutex
}

// EmailProvider represents common email provider configurations
type EmailProvider struct {
	Name     string
	Host     string
	Port     int
	TLS      bool
	OAuth    bool
}


var CommonProviders = map[string]EmailProvider{
	"gmail.com": {
		Name: "Gmail",
		Host: "imap.gmail.com",
		Port: 993,
		TLS:  true,
	},
	"outlook.com": {
		Name: "Outlook",
		Host: "outlook.office365.com",
		Port: 993,
		TLS:  true,
	},
	"hotmail.com": {
		Name: "Outlook",
		Host: "outlook.office365.com", 
		Port: 993,
		TLS:  true,
	},
	"yahoo.com": {
		Name: "Yahoo",
		Host: "imap.mail.yahoo.com",
		Port: 993,
		TLS:  true,
	},
	"fastmail.com": {
		Name: "FastMail",
		Host: "imap.fastmail.com",
		Port: 993,
		TLS:  true,
	},
}

// NewClient creates a new IMAP client for the given email account
func NewClient(email, username, password string, login *bridgev2.UserLogin, log *zerolog.Logger, sanitized bool, secret string, backfillSeconds int, backfillMax int, initialIdleTimeoutSeconds int) (*Client, error) {
	// Auto-detect provider settings
	domain := strings.ToLower(strings.Split(email, "@")[1])
	provider, ok := CommonProviders[domain]
	
	var host string
	var port int
	var useTLS bool
	
	if ok {
		host = provider.Host
		port = provider.Port
		useTLS = provider.TLS
		// SECURE LOGGING: No passwords logged
		log.Info().Str("provider", provider.Name).Str("host", host).Int("port", port).Str("email", email).Msg("Auto-detected email provider")
	} else {
		// Default IMAP settings for unknown providers
		host = fmt.Sprintf("imap.%s", domain)
		port = 993
		useTLS = true
		log.Warn().Str("domain", domain).Str("email", email).Msg("Unknown provider, using default IMAP settings")
	}

	// Create context for proper cancellation
	ctx, cancel := context.WithCancel(context.Background())
	
	// Derive timeouts
	initIdle := 30 * time.Second
	if initialIdleTimeoutSeconds > 0 {
		initIdle = time.Duration(initialIdleTimeoutSeconds) * time.Second
	}
	return &Client{
		Email:        email,
		Host:         host,
		Port:         port,
		Username:     username,
		Password:     password, // Never logged
		TLS:          useTLS,
		login:        login,
		log:          log,
		sanitized:    sanitized,
		secret:       secret,
		stopIdle:     make(chan struct{}),
		reconnect:    make(chan struct{}, 1),
		// Circuit breaker settings
		maxFailures:  5,
		backoffTime:  time.Minute * 2,
		// Context management
		ctx:          ctx,
		cancel:       cancel,
		// Startup behavior
		startupBackfillSeconds: backfillSeconds,
		startupBackfillMax:     backfillMax,
		initialIdleTimeout:     initIdle,
		idleInterval:           30 * time.Second,
		firstIdleCycle:         true,
		// Mailbox management
		sentFolder:             detectSentFolderForProvider(domain),
		// In-flight maps
		inFlightInbox:          make(map[imap.UID]struct{}),
		inFlightSent:           make(map[imap.UID]struct{}),
	}, nil
}

// Connect establishes connection to the IMAP server
func (c *Client) Connect() error {
	// Prevent concurrent connection attempts
	c.connectingMu.Lock()
	defer c.connectingMu.Unlock()
	
	if c.isConnecting {
		return fmt.Errorf("connection already in progress")
	}
	c.isConnecting = true
	defer func() { c.isConnecting = false }()

	return c.connectInternal()
}

// connectInternal performs the actual connection logic without connection guards
// Must be called only when connection guards are already held
func (c *Client) connectInternal() error {
	c.mu.Lock()
	defer c.mu.Unlock()

// If we think we're connected, validate liveness before early return
	if c.connected {
		if err := c.testConnectionNoLock(); err != nil {
			c.log.Warn().Err(err).Msg("Detected dead IMAP connection during Connect - resetting state")
			// Force-clear state so we can rebuild below
			if c.client != nil {
				c.client.Close()
				c.client = nil
			}
			c.connected = false
			c.idling = false
		} else {
			return nil
		}
	}

	// Ensure clean state before connecting
	c.idling = false
	c.connected = false
	
	c.log.Info().Str("host", c.Host).Int("port", c.Port).Bool("tls", c.TLS).Msg("Connecting to IMAP server")

	// Create network connection
	addr := net.JoinHostPort(c.Host, fmt.Sprintf("%d", c.Port))
	var conn net.Conn
	var err error

	if c.TLS {
		conn, err = tls.Dial("tcp", addr, &tls.Config{
			ServerName: c.Host,
		})
	} else {
		conn, err = net.Dial("tcp", addr)
	}

	if err != nil {
		c.log.Error().Err(err).Str("address", addr).Msg("Failed to establish network connection to IMAP server")
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}

	// Create IMAP client with debug logging enabled
	debugWriter := &IMAPDebugWriter{logger: c.log, sanitized: c.sanitized}
	c.client = imapclient.New(conn, &imapclient.Options{
		DebugWriter: debugWriter, // Enable full IMAP protocol debugging
	})

	// Authenticate
	if err := c.client.Login(c.Username, c.Password).Wait(); err != nil {
		c.log.Error().Err(err).Str("username", c.Username).Msg("IMAP authentication failed")
		conn.Close()
		return fmt.Errorf("IMAP login failed: %w", err)
	}

	c.connected = true
	c.log.Info().Msg("Successfully connected to IMAP server")

	return nil
}

// Disconnect closes the IMAP connection
func (c *Client) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil
	}

	// Stop IDLE if running
	if c.idling {
		select {
		case <-c.stopIdle:
			// Already closed
		default:
			close(c.stopIdle)
		}
		c.idling = false
	}

	// Close INBOX connection
	if c.client != nil {
		// Attempt graceful logout with timeout; force-close on timeout
		done := make(chan error, 1)
		go func() {
			if err := c.client.Logout().Wait(); err != nil {
				done <- err
				return
			}
			done <- nil
		}()
		select {
		case err := <-done:
			if err != nil {
				c.log.Warn().Err(err).Msg("Error during IMAP logout")
			}
		case <-time.After(2 * time.Second):
			c.log.Warn().Msg("IMAP logout timed out, force closing connection")
		}
		c.client.Close()
		c.client = nil
	}

	c.connected = false
	c.log.Info().Msg("Disconnected from IMAP server (INBOX)")

	// Close Sent connection
	c.sentMu.Lock()
	if c.sentClient != nil {
		if c.sentStop != nil {
			select { case <-c.sentStop: default: close(c.sentStop) }
		}
		c.sentClient.Close()
		c.sentClient = nil
		c.sentConnected = false
	}
	c.sentMu.Unlock()
	
	return nil
}

// StartIDLE begins IMAP IDLE monitoring for real-time email delivery
func (c *Client) StartIDLE() (err error) {
	c.mu.Lock()
	
	// Check if already idling to prevent concurrent IDLE attempts
	if c.idling {
		c.mu.Unlock()
		return fmt.Errorf("IDLE already running")
	}
	if !c.connected {
		c.mu.Unlock()
		return fmt.Errorf("not connected to IMAP server")
	}
	
	// Create a fresh stop channel for this IDLE session
	c.stopIdle = make(chan struct{})
	c.idling = true
	// Keep mutex locked until critical setup is complete
	defer func() {
		if err != nil {
			// Reset state on error
			c.mu.Lock()
			c.idling = false
			c.mu.Unlock()
		}
	}()
	
	// Get a local reference to the client while protected by mutex
	client := c.client
	c.mu.Unlock()

	c.log.Info().Msg("Starting IMAP IDLE monitoring")

	// Select INBOX - this will reset any stale connection state
	if _, err := client.Select("INBOX", nil).Wait(); err != nil {
		return fmt.Errorf("failed to select INBOX: %w", err)
	}

	// Establish immediate baseline and optional backfill BEFORE starting IDLE (INBOX)
	if err := c.primeBaselineAndBackfillFor(client, "INBOX", false); err != nil {
		return fmt.Errorf("failed to prime baseline/backfill: %w", err)
	}

	// Test IDLE capability before starting the loop
	// This will fail immediately if server thinks IDLE is already running
	c.log.Trace().Msg("Probing IDLE capability with a short-lived test call")
	testIdleCmd, err := client.Idle()
	if err != nil {
		// If IDLE is "already running", force a reconnection to reset server state
		if strings.Contains(err.Error(), "already running") || strings.Contains(err.Error(), "IDLE already") {
			c.log.Warn().Err(err).Msg("Server reports IDLE already running - forcing connection reset")
			return c.resetConnection()
		}
		return fmt.Errorf("failed to test IDLE capability: %w", err)
	}
	
	// Immediately close the test IDLE and start the actual monitoring loop
	if err := testIdleCmd.Close(); err != nil {
		c.log.Warn().Err(err).Msg("Failed to close test IDLE command")
	} else {
		c.log.Trace().Msg("Closed test IDLE successfully; proceeding to start monitoring loop")
	}

	// Start IDLE monitoring in goroutine
	go c.idleLoop()

	// Start dedicated Sent connection if configured/available
	if c.sentFolder != "" {
		go c.ensureSentConnectionAndLoop()
	}

	return nil
}

// StopIDLE stops IMAP IDLE monitoring
func (c *Client) StopIDLE() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.idling {
		return
	}

	c.log.Info().Msg("Stopping IMAP IDLE monitoring")
	
	// Safely close channel only if not already closed
	select {
	case <-c.stopIdle:
		// Already closed
	default:
		close(c.stopIdle)
	}
	
	// Do NOT recreate stopIdle here to avoid losing the stop signal in the running goroutine
	c.idling = false
}

// idleLoop runs the IMAP IDLE monitoring loop
func (c *Client) idleLoop() {
	defer func() {
		c.mu.Lock()
		c.idling = false
		c.mu.Unlock()
	}()

	for {
		select {
		case <-c.stopIdle:
			c.log.Debug().Msg("IDLE monitoring stopped")
			return
		case <-c.reconnect:
			c.log.Info().Msg("Reconnecting IMAP client (signal)")
			if err := c.reconnectClient(); err != nil {
				c.log.Error().Err(err).Msg("Failed to reconnect (signal)")
				// Wait before retrying
				time.Sleep(30 * time.Second)
				continue
			}
			// After successful reconnect, loop to start IDLE again
			continue
		default:
			if err := c.runIDLE(); err != nil {
				c.log.Error().Err(err).Msg("IDLE failed, performing full reconnect")
				// Demote bridge state for this login while we attempt recovery
				c.sendBridgeState(status.BridgeState{
					StateEvent: status.StateUnknownError,
					Source:     "network",
					Info:       map[string]any{"component": "imap", "reason": "idle_failed"},
					TTL:        300,
				})
				if recErr := c.reconnectClient(); recErr != nil {
					c.log.Error().Err(recErr).Msg("Reconnect after IDLE failure failed")
					// Back off before trying again
					time.Sleep(30 * time.Second)
					continue
				}
				c.log.Info().Msg("Reconnected successfully after IDLE failure")
				// Promote bridge state back to connected after successful reconnect
				c.sendBridgeState(status.BridgeState{StateEvent: status.StateConnected})
				continue
			}
		}
	}
}

// runIDLE executes a single IDLE session
func (c *Client) runIDLE() error {
	c.log.Debug().Msg("Starting IDLE session")

	// Ensure client is still connected
	c.mu.RLock()
	connected := c.connected
	cli := c.client
	c.mu.RUnlock()
	if !connected || cli == nil {
		return fmt.Errorf("not connected to IMAP server")
	}

	// Create IDLE command
idleCmd, err := cli.Idle()
	if err != nil {
		// If IDLE fails due to "already running", this indicates server-side state desync
		// Force a reconnection to clean up the connection state
		if strings.Contains(err.Error(), "already running") || strings.Contains(err.Error(), "IDLE already") {
			c.log.Warn().Err(err).Msg("IDLE already running on server - forcing reconnection to reset state")
			// Signal reconnection needed
			c.triggerReconnect()
			return fmt.Errorf("IDLE state desync detected, reconnection triggered: %w", err)
		}
		if isHardNetErr(err) {
			c.mu.Lock()
			if c.client != nil {
				c.client.Close()
				c.client = nil
			}
			c.connected = false
			c.idling = false
			c.mu.Unlock()
		}
		return fmt.Errorf("failed to start IDLE: %w", err)
	}

	c.log.Info().Msg("IDLE session started - waiting for email notifications")

	// The real issue: idleCmd.Wait() hangs instead of returning on server notifications
	// Solution: Use a timeout-based approach that periodically checks for new messages
	// This gives us responsiveness while still using IDLE properly
	
	cycleTimeout := c.idleInterval
	if c.firstIdleCycle && c.initialIdleTimeout > 0 {
		cycleTimeout = c.initialIdleTimeout
		c.firstIdleCycle = false
	}
	timeoutTimer := time.NewTimer(cycleTimeout)
	defer timeoutTimer.Stop()

	for {
		select {
		case <-c.stopIdle:
			c.log.Debug().Msg("IDLE stop signal received")
			idleCmd.Close()
			return nil
			
		case <-timeoutTimer.C:
			c.log.Debug().Msg("IDLE timeout reached, checking for messages and restarting")
			// Close current IDLE session
			idleCmd.Close()
			
			// Check for new messages
			if err := c.CheckNewMessages(); err != nil {
				c.log.Error().Err(err).Msg("Error checking new messages on IDLE timeout")
			}
			
			// Restart IDLE for next cycle
			return nil // This will cause idleLoop to restart IDLE
		}
	}
}

// primeBaselineAndBackfill sets lastUID to UIDNEXT-1 and optionally backfills recent messages
func (c *Client) primeBaselineAndBackfillFor(cli *imapclient.Client, mailbox string, isSent bool) error {
	// Ensure client is available
	// Use provided client handle
	if cli == nil {
		return fmt.Errorf("IMAP client not available during primeBaselineAndBackfill")
	}
	// Ensure INBOX is selected to avoid using a stale/unknown mailbox
	if _, err := cli.Select(mailbox, nil).Wait(); err != nil {
		return fmt.Errorf("failed to select INBOX during prime: %w", err)
	}
	statusCmd := cli.Status(mailbox, &imap.StatusOptions{UIDNext: true})
	statusData, err := statusCmd.Wait()
	if err != nil {
		return fmt.Errorf("failed to get INBOX status during prime: %w", err)
	}
	baseline := statusData.UIDNext - 1
	c.mu.Lock()
	if isSent {
		c.lastSentUID = baseline
	} else {
		c.lastInboxUID = baseline
	}
	c.mu.Unlock()
	c.log.Info().Uint32("uidnext", uint32(statusData.UIDNext)).Uint32("baseline_uid", uint32(baseline)).Str("mailbox", mailbox).Msg("Established baseline UID at startup")
	if c.startupBackfillSeconds <= 0 || c.startupBackfillMax <= 0 {
		c.log.Trace().Msg("Startup backfill disabled or not configured")
		return nil
	}
	since := time.Now().Add(-time.Duration(c.startupBackfillSeconds) * time.Second)
	uidSet := imap.UIDSet{}
	uidSet.AddRange(baseline+1, 0)
	criteria := imap.SearchCriteria{Since: since, UID: []imap.UIDSet{uidSet}}
	c.log.Info().Time("since", since).Int("max", c.startupBackfillMax).Str("mailbox", mailbox).Msg("Running startup backfill search")
	// Issue search on the provided client
	searchCmd := cli.UIDSearch(&criteria, nil)
	searchData, err := searchCmd.Wait()
	if err != nil {
		return fmt.Errorf("startup backfill search failed: %w", err)
	}
	uids := searchData.AllUIDs()
	if len(uids) == 0 {
		c.log.Info().Msg("Startup backfill: no messages found")
		return nil
	}
	if len(uids) > c.startupBackfillMax {
		uids = uids[len(uids)-c.startupBackfillMax:]
	}
	c.log.Info().Int("count", len(uids)).Msg("Startup backfill: processing messages")
	var highest imap.UID = baseline
	for _, uid := range uids {
		if uid <= baseline {
			continue
		}
		if err := c.processMessageWith(context.Background(), cli, uid, mailbox); err != nil {
			c.log.Error().Err(err).Uint32("uid", uint32(uid)).Msg("Startup backfill: failed to process message")
			continue
		}
		if uid > highest {
			highest = uid
		}
	}
	if highest > baseline {
		c.mu.Lock()
		if isSent {
			c.lastSentUID = highest
		} else {
			c.lastInboxUID = highest
		}
		c.mu.Unlock()
		c.log.Info().Uint32("last_uid", uint32(highest)).Str("mailbox", mailbox).Msg("Startup backfill: updated lastUID after processing")
	}
	c.log.Info().Str("mailbox", mailbox).Msg("IMAP ready for new messages after baseline/backfill")
	return nil
}

// checkNewMessages fetches and processes new messages
func (c *Client) checkNewMessagesFor(cli *imapclient.Client, mailbox string, isSent bool) error {
	c.log.Info().Msg("[SYNC] Starting manual sync - checking for new messages")
	
	// Guard against nil client handles to avoid panics
	if cli == nil {
		return fmt.Errorf("imap client unavailable for %s", mailbox)
	}
	
	// Get current lastUID safely
	c.mu.RLock()
	var currentLastUID imap.UID
	if isSent {
		currentLastUID = c.lastSentUID
	} else {
		currentLastUID = c.lastInboxUID
	}
	c.mu.RUnlock()
	
	// Use SEARCH command to find new messages without affecting IDLE state
	c.log.Info().Uint32("from_uid", uint32(currentLastUID+1)).Uint32("current_last_uid", uint32(currentLastUID)).Str("mailbox", mailbox).Msg("Searching for new messages")
	
	// Create UID set for messages after our last processed UID
	uidSet := imap.UIDSet{}
	uidSet.AddRange(currentLastUID+1, 0) // 0 means "to end"
	
	// Search for messages with UIDs in this range
	searchCriteria := imap.SearchCriteria{
		UID: []imap.UIDSet{uidSet},
	}
	
	// If this is the first sync (lastUID=0), just get current state and mark as up-to-date
	if currentLastUID == 0 {
		c.log.Info().Msg("First sync detected (lastUID=0), setting up to only sync NEW messages going forward")
		c.log.Warn().Msg("First sync policy will SKIP any messages already in INBOX. Consider backfill if needed.")
		// Get the current highest UID to mark as our starting point
		c.log.Debug().Str("mailbox", mailbox).Msg("[IMAP] Executing STATUS command to get UIDNext")
statusCmd := cli.Status(mailbox, &imap.StatusOptions{
			UIDNext: true,
		})
statusData, err := statusCmd.Wait()
		if err != nil {
			c.log.Error().Err(err).Msg("Failed to get INBOX status")
			if isHardNetErr(err) {
				c.mu.Lock()
				if c.client != nil {
					c.client.Close()
					c.client = nil
				}
				c.connected = false
				c.idling = false
				c.mu.Unlock()
			}
			return fmt.Errorf("failed to get INBOX status: %w", err)
		}
		
		c.log.Info().Uint32("uidnext", uint32(statusData.UIDNext)).Str("mailbox", mailbox).Msg("[IMAP] STATUS command completed")
		
		// Set lastUID to current highest UID so we only sync NEW messages from now on
		currentHighestUID := statusData.UIDNext - 1
		c.mu.Lock()
		if isSent {
			c.lastSentUID = currentHighestUID
		} else {
			c.lastInboxUID = currentHighestUID
		}
		c.mu.Unlock()
		
		c.log.Info().Uint32("last_uid", uint32(currentHighestUID)).Str("mailbox", mailbox).Msg("First sync complete - up-to-date, will only sync NEW messages")
		c.log.Trace().Uint32("uidnext", uint32(statusData.UIDNext)).Uint32("baseline_uid", uint32(currentHighestUID)).Str("mailbox", mailbox).Msg("Established baseline UID at startup")
		return nil // No need to search for existing messages
	}
	
	c.log.Debug().Interface("search_criteria", searchCriteria).Msg("Starting IMAP UID search")
	
	// Create search command with timeout handling
searchCmd := cli.UIDSearch(&searchCriteria, nil)
	var newUIDs []imap.UID
	
	// Wait for search results with timeout
	c.log.Debug().Msg("Waiting for IMAP search results")
	
	// Create a timeout channel for the search operation
	searchDone := make(chan struct{
		result *imap.SearchData
		err    error
	}, 1)
	
	go func() {
		result, err := searchCmd.Wait()
		searchDone <- struct {
			result *imap.SearchData
			err    error
		}{result: result, err: err}
	}()
	
	// Wait with timeout
	var searchResult *imap.SearchData
	select {
case response := <-searchDone:
		if response.err != nil {
			c.log.Error().Err(response.err).Msg("Failed to search for new messages")
			if isHardNetErr(response.err) {
				c.mu.Lock()
				if c.client != nil {
					c.client.Close()
					c.client = nil
				}
				c.connected = false
				c.idling = false
				c.mu.Unlock()
			}
			return fmt.Errorf("failed to search for new messages: %w", response.err)
		}
		searchResult = response.result
case <-time.After(30 * time.Second):
		c.log.Error().Msg("IMAP search timed out after 30 seconds")
		return fmt.Errorf("IMAP search timed out")
	}
	
	c.log.Debug().Msg("IMAP search completed")
	
	// Get the UIDs from search results
	newUIDs = searchResult.AllUIDs()
	
	// Filter out any UIDs that are not strictly newer than our last processed UID
	{
		c.mu.RLock()
		last := currentLastUID
		c.mu.RUnlock()
		filtered := make([]imap.UID, 0, len(newUIDs))
		for _, uid := range newUIDs {
			if uid > last {
				filtered = append(filtered, uid)
			}
		}
		newUIDs = filtered
	}
	
	if len(newUIDs) == 0 {
		c.log.Info().Msg("No new messages found")
		return nil
	}
	
	c.log.Info().Int("count", len(newUIDs)).Str("mailbox", mailbox).Msg("Found new messages")
	
	// Update lastUID before processing to prevent reprocessing the same messages
	// even if processing fails for individual messages
	if len(newUIDs) > 0 {
		// Find the highest UID
		highestUID := newUIDs[0]
		for _, uid := range newUIDs[1:] {
			if uid > highestUID {
				highestUID = uid
			}
		}
		
		c.mu.Lock()
		if isSent {
			c.lastSentUID = highestUID
		} else {
			c.lastInboxUID = highestUID
		}
		c.mu.Unlock()
		c.log.Info().Uint32("new_last_uid", uint32(highestUID)).Str("mailbox", mailbox).Msg("Updated lastUID before processing to prevent reprocessing")
	}
	
	// Process the new messages
	for _, uid := range newUIDs {
		// De-duplicate concurrent processing of the same UID
		if !c.startUID(uid, isSent) {
			c.log.Debug().Uint32("uid", uint32(uid)).Str("mailbox", mailbox).Msg("UID is already being processed, skipping")
			continue
		}
		if err := c.processMessageWith(context.Background(), cli, uid, mailbox); err != nil {
			c.log.Error().Err(err).Uint32("uid", uint32(uid)).Msg("Failed to process message - will not reprocess this UID")
			// Continue processing other messages even if one fails
			// Note: lastUID was already updated above, so this message won't be reprocessed
		}
		c.endUID(uid, isSent)
	}
	
	c.log.Info().Str("mailbox", mailbox).Msg("Sync completed successfully")
	return nil
}

// SetProcessor sets the email processor for this client
func (c *Client) SetProcessor(processor *email.Processor) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.processor = processor
}


// getPortalLock returns a mutex for a given portal ID, creating it if needed
func (c *Client) getPortalLock(id string) *sync.Mutex {
	if mu, ok := c.portalLocks.Load(id); ok {
		return mu.(*sync.Mutex)
	}
	newMu := &sync.Mutex{}
	actual, _ := c.portalLocks.LoadOrStore(id, newMu)
	return actual.(*sync.Mutex)
}

// ensurePortalRoom ensures the Matrix room exists for the given portal.
// It is safe to call concurrently; creation will be serialized per-portal.
func (c *Client) ensurePortalRoom(ctx context.Context, portal *bridgev2.Portal) error {
	if portal == nil {
		return fmt.Errorf("nil portal")
	}
	id := string(portal.ID)
	mu := c.getPortalLock(id)
	mu.Lock()
	defer mu.Unlock()

	// Re-check after acquiring lock
	if portal.MXID != "" {
		return nil
	}

	// Attempt to create the room with small retries for transient errors
	var lastErr error
	for i := 0; i < 3; i++ {
		c.log.Info().Str("portal_id", id).Int("attempt", i+1).Msg("Creating Matrix room for portal")
		// Note: Depending on mautrix bridgev2 version, an Ensure* method may exist.
		// We use CreateMatrixRoom here; it's expected to be idempotent if the room already got created.
		if err := portal.CreateMatrixRoom(ctx, c.login, nil); err != nil {
			lastErr = err
			c.log.Warn().Err(err).Str("portal_id", id).Int("attempt", i+1).Msg("CreateMatrixRoom failed, will retry")
			time.Sleep(time.Duration(100*(i+1)) * time.Millisecond)
			continue
		}
		if portal.MXID != "" {
			c.log.Info().Str("portal_id", id).Str("mxid", portal.MXID.String()).Msg("Matrix room created for portal")
			return nil
		}
		// If still empty, brief wait and recheck
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("failed to create Matrix room: %w", lastErr)
}

// processMessage fetches and processes a single email message
func (c *Client) processMessageWith(ctx context.Context, cli *imapclient.Client, uid imap.UID, mailbox string) error {
	c.log.Debug().Uint32("uid", uint32(uid)).Msg("Fetching message")

	// Fetch message with headers and body
	fetchOptions := &imap.FetchOptions{
		Envelope: true,
		BodyStructure: &imap.FetchItemBodyStructure{},
		Flags: true,
		UID: true,
	}

	// Also fetch headers, text content, and the full raw body so MIME parts (HTML/attachments) are available
	fetchOptions.BodySection = []*imap.FetchItemBodySection{
		{Specifier: imap.PartSpecifierHeader},
		{Specifier: imap.PartSpecifierText},
		{Specifier: imap.PartSpecifierNone}, // full message body
	}

	// Create UID set and execute fetch command
	uidSet := imap.UIDSetNum(uid)
	fetchCmd := cli.Fetch(uidSet, fetchOptions)
	defer fetchCmd.Close()

	// Process the fetched message
	for {
		msg := fetchCmd.Next()
		if msg == nil {
			break
		}

		// Skip processing if login is nil (testing mode)
		if c.login == nil {
			c.log.Debug().Msg("Skipping message processing (test mode)")
			return nil
		}

		// Process the message using the email processor, with a one-time degraded-parse retry
		emailMessage, err := c.processor.ProcessIMAPMessage(ctx, msg, c.login, mailbox)
		if err != nil {
			// If processor reports a degraded parse (missing From/Message-ID), try a short retry
			if strings.Contains(strings.ToLower(err.Error()), "degraded parse") {
				c.log.Warn().Uint32("uid", uint32(uid)).Str("mailbox", mailbox).Msg("Degraded parse detected, retrying fetch once")
				// brief delay to allow server to settle
				time.Sleep(200 * time.Millisecond)
				// Re-fetch
				refetchOpts := &imap.FetchOptions{
					Envelope:      true,
					BodyStructure: &imap.FetchItemBodyStructure{},
					Flags:         true,
					UID:           true,
					BodySection: []*imap.FetchItemBodySection{
						{Specifier: imap.PartSpecifierHeader},
						{Specifier: imap.PartSpecifierText},
						{Specifier: imap.PartSpecifierNone},
					},
				}
				refetch := cli.Fetch(imap.UIDSetNum(uid), refetchOpts)
				defer refetch.Close()
				if m := refetch.Next(); m != nil {
					emailMessage, err = c.processor.ProcessIMAPMessage(ctx, m, c.login, mailbox)
				}
			}
			if err != nil {
				// Drop the event instead of creating a bad portal/room on degraded parse
				return fmt.Errorf("failed to process IMAP message: %w", err)
			}
		}

		// Convert to Matrix event and queue it
		matrixEvent := c.processor.ToMatrixEvent(ctx, emailMessage, c.login)

		// Ensure portal exists before queuing the event
		portalKey := emailMessage.PortalKey
		c.log.Info().Str("portal_key", string(portalKey.ID)).Str("receiver", string(portalKey.Receiver)).Msg("Checking if portal exists before queuing event")
		
		// Debug: Log detailed portal key information
		c.log.Debug().Interface("portal_key_full", portalKey).Msg("Full portal key details")
		
		portal, err := c.login.Bridge.GetExistingPortalByKey(ctx, portalKey)
		if err != nil {
			c.log.Error().Err(err).Str("portal_key", string(portalKey.ID)).Msg("Failed to check existing portal")
			return fmt.Errorf("failed to check portal existence: %w", err)
		}
		
		if portal == nil {
			c.log.Info().Str("portal_key", string(portalKey.ID)).Msg("Portal doesn't exist, creating it")
			// Create the portal - this will call GetChatInfo to set up the room
			portal, err = c.login.Bridge.GetPortalByKey(ctx, portalKey)
			if err != nil {
				c.log.Error().Err(err).Str("portal_key", string(portalKey.ID)).Msg("Failed to create portal")
				return fmt.Errorf("failed to create portal for email thread: %w", err)
			}
			c.log.Info().Str("portal_key", string(portalKey.ID)).Interface("portal", portal).Msg("Successfully created portal for email thread")
		} else {
			c.log.Info().Str("portal_key", string(portalKey.ID)).Str("portal_mxid", portal.MXID.String()).Interface("portal_info", portal).Msg("Portal already exists - no need to create")
		}
		
		// CRITICAL: Force Matrix room creation if portal exists but has no MXID
		if portal.MXID == "" {
			c.log.Info().Str("portal_key", string(portalKey.ID)).Msg("Portal exists but has no Matrix room - forcing room creation")
			// Force room creation by calling the portal's CreateMatrixRoom method
			if err := portal.CreateMatrixRoom(ctx, c.login, nil); err != nil {
				c.log.Error().Err(err).Str("portal_key", string(portalKey.ID)).Msg("Failed to force create Matrix room")
				return fmt.Errorf("failed to create Matrix room for portal: %w", err)
			}
			c.log.Info().Str("portal_key", string(portalKey.ID)).Str("new_mxid", portal.MXID.String()).Msg("Successfully forced Matrix room creation")
		}
		
		// Ensure the Matrix room exists (idempotent, concurrency-safe)
		if err := c.ensurePortalRoom(ctx, portal); err != nil {
			c.log.Error().Err(err).Str("portal_key", string(portalKey.ID)).Msg("Failed to ensure Matrix room exists for portal")
			return err
		}

		// Queue the event with the bridge framework
		if !c.login.QueueRemoteEvent(matrixEvent).Success {
			if c.sanitized {
				c.log.Error().
					Str("message_id_hash", logging.HashHMAC(string(emailMessage.MessageID), c.secret, 10)).
					Str("subject_hash", logging.HashHMAC(logging.BoundAndClean(emailMessage.Subject, 256), c.secret, 10)).
					Msg("Failed to queue remote event")
			} else {
				c.log.Error().
					Str("message_id", string(emailMessage.MessageID)).
					Str("subject", logging.BoundAndClean(emailMessage.Subject, 256)).
					Msg("Failed to queue remote event")
			}
		} else {
			if c.sanitized {
				c.log.Info().
					Str("message_id_hash", logging.HashHMAC(string(emailMessage.MessageID), c.secret, 10)).
					Str("subject_hash", logging.HashHMAC(logging.BoundAndClean(emailMessage.Subject, 256), c.secret, 10)).
					Msg("Successfully queued email message")
			} else {
				c.log.Info().
					Str("message_id", string(emailMessage.MessageID)).
					Str("subject", logging.BoundAndClean(emailMessage.Subject, 256)).
					Msg("Successfully queued email message")
			}
		}
	}

	// Wait for fetch to complete
	if err := fetchCmd.Close(); err != nil {
		return fmt.Errorf("fetch command failed: %w", err)
	}

	return nil
}

// reconnectClient attempts to reconnect to the IMAP server with circuit breaker
func (c *Client) reconnectClient() error {
	// Acquire connection guard to prevent concurrent reconnect attempts
	c.connectingMu.Lock()
	defer c.connectingMu.Unlock()
	
	if c.isConnecting {
		return fmt.Errorf("connection operation already in progress")
	}
	c.isConnecting = true
	defer func() { c.isConnecting = false }()
	
	c.mu.Lock()
	// Check circuit breaker
	if c.failureCount >= c.maxFailures {
		if time.Since(c.lastFailure) < c.backoffTime {
			c.mu.Unlock()
			return fmt.Errorf("circuit breaker open: too many failures (%d), waiting %v", c.failureCount, c.backoffTime-time.Since(c.lastFailure))
		}
		// Reset circuit breaker after backoff period
		c.log.Info().Msg("Circuit breaker reset: attempting reconnection")
		c.failureCount = 0
	}
	failureCount := c.failureCount
	c.mu.Unlock()
	
	// Disconnect first
	c.Disconnect()
	
	// Calculate exponential backoff (min 5s, max 5min) with jitter (+/-20%)
	base := time.Duration(failureCount+1) * 5 * time.Second
	if base > 5*time.Minute {
		base = 5 * time.Minute
	}
	jitterFraction := 0.2
	jitter := time.Duration(float64(base) * (rand.Float64()*2*jitterFraction - jitterFraction))
	backoffDuration := base + jitter
	if backoffDuration < 0 {
		backoffDuration = base // avoid negative
	}
	c.log.Info().Dur("backoff", backoffDuration).Int("failure_count", failureCount).Msg("Waiting before reconnection attempt")
	time.Sleep(backoffDuration)
	
	// Reconnect (bypass Connect's own guard since we already hold it)
	if err := c.connectInternal(); err != nil {
		c.mu.Lock()
		c.failureCount++
		c.lastFailure = time.Now()
		c.mu.Unlock()
		c.log.Error().Err(err).Int("failure_count", c.failureCount).Msg("Reconnection failed")
		return err
	}
	
	// Reselect INBOX
	if _, err := c.client.Select("INBOX", nil).Wait(); err != nil {
		c.mu.Lock()
		c.failureCount++
		c.lastFailure = time.Now()
		c.mu.Unlock()
		return fmt.Errorf("failed to reselect INBOX: %w", err)
	}
	
	// Success - reset failure counter
	c.mu.Lock()
	c.failureCount = 0
	c.mu.Unlock()
	c.log.Info().Msg("Successfully reconnected to IMAP server")
	
	return nil
}

// Shutdown gracefully shuts down the client
func (c *Client) Shutdown() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if c.isShutdown {
		return
	}
	c.isShutdown = true
	
	c.log.Info().Msg("Shutting down IMAP client")
	
	// Cancel context to stop all operations
	if c.cancel != nil {
		c.cancel()
	}
	
	// Stop IDLE
	if c.idling {
		select {
		case <-c.stopIdle:
		default:
			close(c.stopIdle)
		}
		c.idling = false
	}
	
	// Disconnect
	c.Disconnect()
}

// Reconnect is a public wrapper to trigger a full IMAP reconnection
func (c *Client) Reconnect() error {
	return c.reconnectClient()
}

// IsConnected returns whether the client is currently connected
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// IsIDLERunning returns whether IDLE monitoring is active
func (c *Client) IsIDLERunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.idling
}

// IsReconnecting returns whether a connection operation is currently in progress
func (c *Client) IsReconnecting() bool {
	c.connectingMu.Lock()
	defer c.connectingMu.Unlock()
	return c.isConnecting
}

// CheckNewMessages is a public method to manually check for new messages
// This can be called during periodic sync or when IDLE is not running
func (c *Client) CheckNewMessages() error {
	// Default to syncing INBOX for public manual syncs
	const mailbox = "INBOX"
	const isSent = false
	c.mu.RLock()
	connected := c.connected
	idling := c.idling
	c.mu.RUnlock()
	
	if !connected {
		return fmt.Errorf("IMAP client not connected")
	}
	
	// If IDLE is running, we need to temporarily stop it to run Status command
	if idling {
		c.log.Info().Msg("Temporarily stopping IDLE for manual sync")
		c.StopIDLE()
		
		// Wait for IDLE to fully stop with timeout
		timeout := time.After(2 * time.Second)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		
		for {
			select {
			case <-timeout:
				c.log.Warn().Msg("Timeout waiting for IDLE to stop, proceeding anyway")
				goto runSync
			case <-ticker.C:
				c.mu.RLock()
				stillIdling := c.idling
				c.mu.RUnlock()
				if !stillIdling {
					c.log.Info().Msg("IDLE fully stopped, proceeding with sync")
					goto runSync
				}
			}
		}
		
		runSync:
	// Run the sync for the specified mailbox
		err := c.checkNewMessagesFor(c.client, mailbox, isSent)
		
		// Restart IDLE with retry logic (same as startup)
		c.log.Info().Msg("Restarting IDLE after manual sync")
		if restartErr := c.safeStartIDLE(); restartErr != nil {
			c.log.Error().Err(restartErr).Msg("Failed to restart IDLE after sync")
			// Don't fail the sync command due to IDLE restart issues
			// The sync itself was successful, IDLE can be retried by the background loops
			c.log.Warn().Msg("Sync completed successfully, but IDLE restart failed - periodic sync will continue")
		}
		
		return err
	}
	
	// IDLE not running, safe to check messages directly
	return c.checkNewMessagesFor(c.client, mailbox, isSent)
}

// TestConnection tests if the IMAP connection is healthy by sending a NOOP command
func (c *Client) TestConnection() error {
	c.mu.RLock()
	connected := c.connected
	client := c.client
	c.mu.RUnlock()
	
	if !connected || client == nil {
		return fmt.Errorf("IMAP client not connected")
	}
	
	// Send NOOP command to test connection health
	// This will fail if the connection is stale or if there are server-side issues
	noopCmd := client.Noop()
	if err := noopCmd.Wait(); err != nil {
		// If this looks like a hard network error, force-clear state so callers can reconnect
		if isHardNetErr(err) {
			c.mu.Lock()
			if c.client != nil {
				c.client.Close()
				c.client = nil
			}
			c.connected = false
			c.idling = false
			c.mu.Unlock()
		}
		return fmt.Errorf("NOOP command failed: %w", err)
	}
	
	c.log.Debug().Msg("Connection test successful (NOOP command completed)")
	return nil
}

// safeStartIDLE attempts to start IDLE with timeout and recovery logic
func (c *Client) safeStartIDLE() error {
	// Use a timeout channel to prevent hanging
	done := make(chan error, 1)
	go func() {
		// Try to start IDLE with connection reset capability
		if err := c.TestConnection(); err != nil {
			c.log.Warn().Err(err).Msg("Connection test failed during IDLE restart - performing full reconnect")
			if reconErr := c.reconnectClient(); reconErr != nil {
				done <- fmt.Errorf("failed to reconnect for IDLE restart: %w", reconErr)
				return
			}
		}
		
		// Try starting IDLE
		if err := c.StartIDLE(); err != nil {
			// Check for the "already running" issue
			if strings.Contains(err.Error(), "already running") || strings.Contains(err.Error(), "IDLE already") {
				c.log.Warn().Err(err).Msg("IDLE already running during restart - attempting connection reset")
				// Try connection reset
				if resetErr := c.resetConnection(); resetErr != nil {
					done <- fmt.Errorf("failed to reset connection for IDLE restart: %w", resetErr)
					return
				}
				done <- nil // Success after reset
				return
			}
			done <- fmt.Errorf("failed to start IDLE: %w", err)
			return
		}
		done <- nil // Success
	}()
	
// Wait with timeout
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		c.log.Error().Msg("IDLE restart timed out after 10 seconds")
		return fmt.Errorf("IDLE restart timed out")
	}
}

// testConnectionNoLock assumes the caller holds c.mu and only checks current handle liveness.
// This function MUST be called with c.mu held to avoid race conditions.
func (c *Client) testConnectionNoLock() error {
	// Note: c.mu must be held by caller - no additional locking here
	if !c.connected || c.client == nil {
		return fmt.Errorf("IMAP client not connected")
	}
	return c.client.Noop().Wait()
}


// ensureSentConnectionAndLoop establishes and maintains a second IMAP connection to the
// Sent mailbox. It primes baseline/backfill and then starts a parallel IDLE loop.
func (c *Client) ensureSentConnectionAndLoop() {
	c.sentMu.Lock()
	if c.sentClient != nil || c.sentFolder == "" {
		c.sentMu.Unlock()
		return
	}
	c.sentStop = make(chan struct{})
	c.sentFailureCount = 0
	c.sentMu.Unlock()

	rebuild := func() (*imapclient.Client, error) {
		addr := net.JoinHostPort(c.Host, fmt.Sprintf("%d", c.Port))
		var conn net.Conn
		var err error
		if c.TLS {
			conn, err = tls.Dial("tcp", addr, &tls.Config{ServerName: c.Host})
		} else {
			conn, err = net.Dial("tcp", addr)
		}
		if err != nil {
			return nil, err
		}
		cli := imapclient.New(conn, &imapclient.Options{DebugWriter: &IMAPDebugWriter{logger: c.log, sanitized: c.sanitized}})
		if err := cli.Login(c.Username, c.Password).Wait(); err != nil {
			conn.Close()
			return nil, err
		}
		if _, err := cli.Select(c.sentFolder, nil).Wait(); err != nil {
			cli.Close()
			return nil, err
		}
		return cli, nil
	}

	cli, err := rebuild()
	if err != nil {
		c.log.Warn().Err(err).Msg("Failed to establish Sent connection; falling back to legacy polling via INBOX")
		return
	}

	// Prime baseline/backfill for Sent on dedicated connection
	if err := c.primeBaselineAndBackfillFor(cli, c.sentFolder, true); err != nil {
		c.log.Warn().Err(err).Msg("Failed to prime Sent mailbox on dedicated connection")
	}

	c.sentMu.Lock()
	c.sentClient = cli
	c.sentConnected = true
	stopCh := c.sentStop
	c.sentMu.Unlock()

	c.log.Info().Str("mailbox", c.sentFolder).Msg("Started dedicated Sent mailbox connection")

	// Start IDLE loop on dedicated Sent connection
	go c.sentIdleLoop(cli, stopCh)
	// Start periodic health checker for Sent
	go c.sentHealthLoop(stopCh)
}

// sentIdleLoop runs an IDLE session on the Sent connection in parallel to INBOX.
// It mirrors the INBOX IDLE logic: IDLE with a periodic timeout to check for new messages,
// then re-enter IDLE. This keeps Sent attribution timely without affecting INBOX.
func (c *Client) sentIdleLoop(cli *imapclient.Client, stopCh <-chan struct{}) {
	c.sentMu.Lock()
	c.sentIdling = true
	c.sentMu.Unlock()
	defer func() {
		c.sentMu.Lock()
		c.sentIdling = false
		c.sentMu.Unlock()
	}()

	reconnectSent := func(reason error) {
		// Exponential backoff with jitter for Sent-only failures
		c.sentMu.Lock()
		c.sentFailureCount++
		c.sentLastFailure = time.Now()
		failureCount := c.sentFailureCount
		if c.sentClient != nil {
			c.sentClient.Close()
			c.sentClient = nil
		}
		c.sentConnected = false
		stopChLocal := c.sentStop
		c.sentMu.Unlock()
		if stopChLocal != nil {
			select { case <-stopChLocal: default: }
		}
		base := time.Duration(failureCount) * 5 * time.Second
		if base > 5*time.Minute { base = 5 * time.Minute }
		jitter := time.Duration((rand.Float64()*0.4 - 0.2) * float64(base))
		backoff := base + jitter
		if backoff < 0 { backoff = base }
		c.log.Warn().Dur("backoff", backoff).Err(reason).Msg("Rebuilding Sent connection after failure")
		time.Sleep(backoff)
		go c.ensureSentConnectionAndLoop()
	}

	for {
		// Create IDLE command on Sent
		idleCmd, err := cli.Idle()
		if err != nil {
			if isHardNetErr(err) || strings.Contains(strings.ToLower(err.Error()), "already running") {
				reconnectSent(err)
				return
			}
			c.log.Warn().Err(err).Msg("Sent IDLE start failed; will retry after short delay")
			time.Sleep(5 * time.Second)
			continue
		}
		c.log.Info().Str("mailbox", c.sentFolder).Msg("Sent IDLE started")

		// Use same timeout cycle as INBOX to periodically check messages
		cycleTimeout := c.idleInterval
		timer := time.NewTimer(cycleTimeout)
		select {
		case <-stopCh:
			_ = idleCmd.Close()
			return
		case <-timer.C:
			// Close IDLE and check for new messages in Sent
			_ = idleCmd.Close()
			if err := c.checkNewMessagesFor(cli, c.sentFolder, true); err != nil {
				c.log.Warn().Err(err).Str("mailbox", c.sentFolder).Msg("Sent check on IDLE timeout failed")
				// If client handle is bad/unavailable, rebuild Sent connection
				if strings.Contains(strings.ToLower(err.Error()), "imap client unavailable") || isHardNetErr(err) {
					reconnectSent(err)
					return
				}
			}
		}
	}
}

// detectSentFolderForProvider returns a best-effort Sent folder name for a domain.
func detectSentFolderForProvider(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	switch d {
	case "gmail.com", "googlemail.com":
		return "[Gmail]/Sent Mail"
	case "outlook.com", "hotmail.com", "live.com", "msn.com", "office365.com":
		return "Sent Items"
	case "fastmail.com":
		return "Sent"
	default:
		// Best-effort default; may be refined later
		return "Sent"
	}
}

// triggerReconnect attempts to enqueue a reconnect signal without piling up.
func (c *Client) triggerReconnect() {
	select {
	case c.reconnect <- struct{}{}:
	default:
	}
}

// sendBridgeState wraps BridgeState.Send with a small duplicate throttling window
// to avoid spamming identical state/error pairs during brief flaps. It only
// suppresses if both StateEvent and Error match the last sent and the last send
// was within 60 seconds. Otherwise, it forwards to the framework.
func (c *Client) sendBridgeState(state status.BridgeState) {
	if c.login == nil {
		return
	}
	const cooldown = 60 * time.Second
	now := time.Now()
	if state.StateEvent == c.lastStateEvent && state.Error == c.lastStateError && now.Sub(c.lastStateTime) < cooldown {
		c.log.Debug().
			Str("bridge_state", string(state.StateEvent)).
			Str("error", string(state.Error)).
			Dur("since_last", now.Sub(c.lastStateTime)).
			Msg("Throttling duplicate bridge state")
		return
	}
	c.login.BridgeState.Send(state)
	c.lastStateEvent = state.StateEvent
	c.lastStateError = state.Error
	c.lastStateTime = now
}

// sentHealthLoop periodically NOOPs the Sent connection and triggers a rebuild on failure.
func (c *Client) sentHealthLoop(stopCh <-chan struct{}) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			// Perform NOOP test with connection protection
			func() {
				c.sentMu.RLock()
				defer c.sentMu.RUnlock()
				
				if c.sentClient == nil {
					return
				}
				
				// Keep the lock while performing the operation to prevent races
				noop := c.sentClient.Noop()
				if err := noop.Wait(); err != nil {
					if isHardNetErr(err) {
						c.log.Warn().Err(err).Msg("Sent NOOP failed, triggering connection rebuild")
						// We need to upgrade to write lock for cleanup, but we can't do it safely
						// while holding read lock. Signal rebuild in a separate goroutine.
						go func() {
							c.sentMu.Lock()
							defer c.sentMu.Unlock()
							
							// Double-check the client is still the same (avoid race)
							if c.sentClient != nil {
								c.sentClient.Close()
								c.sentClient = nil
								c.sentConnected = false
								go c.ensureSentConnectionAndLoop()
							}
						}()
					}
				}
			}()
		}
	}
}

// startUID marks a UID as in-flight and returns true if we acquired it.
func (c *Client) startUID(uid imap.UID, isSent bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	var m map[imap.UID]struct{}
	if isSent {
		m = c.inFlightSent
	} else {
		m = c.inFlightInbox
	}
	if _, ok := m[uid]; ok {
		return false
	}
	m[uid] = struct{}{}
	return true
}

// endUID clears a UID from in-flight map.
func (c *Client) endUID(uid imap.UID, isSent bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if isSent {
		delete(c.inFlightSent, uid)
	} else {
		delete(c.inFlightInbox, uid)
	}
}

// isHardNetErr classifies hard network errors that require a full reconnect
func isHardNetErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "connection reset by peer") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "unexpected eof") ||
		strings.Contains(s, "eof") ||
		strings.Contains(s, "i/o timeout")
}

// resetConnection forces a complete disconnection and reconnection to clear server-side state
func (c *Client) resetConnection() error {
	// Acquire connection guard to prevent concurrent reset/connect attempts
	c.connectingMu.Lock()
	defer c.connectingMu.Unlock()
	
	if c.isConnecting {
		return fmt.Errorf("connection operation already in progress")
	}
	c.isConnecting = true
	defer func() { c.isConnecting = false }()
	
	c.log.Info().Msg("Resetting IMAP connection to clear server-side IDLE state")
	
	// Force disconnect without proper logout (since server state is already confused)
	c.mu.Lock()
	if c.client != nil {
		c.client.Close() // Force close TCP connection
		c.client = nil
	}
	c.connected = false
	c.idling = false
	c.mu.Unlock()
	
	// Wait a moment for server-side cleanup
	time.Sleep(2 * time.Second)
	
	// Establish fresh connection (bypass Connect's own guard since we already hold it)
	if err := c.connectInternal(); err != nil {
		return fmt.Errorf("failed to reconnect after reset: %w", err)
	}
	
	// Try IDLE again on the fresh connection
	return c.StartIDLE()
}
