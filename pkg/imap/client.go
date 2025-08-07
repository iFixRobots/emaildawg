package imap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/bridgev2"

	"go.mau.fi/mautrix-emaildawg/pkg/email"
)

// Client represents an IMAP connection for a specific email account
type Client struct {
	// Connection details
	Email    string
	Host     string
	Port     int
	Username string
	Password string
	TLS      bool

	// IMAP client
	client     *imapclient.Client
	connected  bool
	idling     bool
	stopIdle   chan struct{}
	reconnect  chan struct{}
	
	// Bridge integration
	login      *bridgev2.UserLogin // Can be nil for testing
	log        *zerolog.Logger
	processor  *email.Processor

	// Threading
	mu         sync.RWMutex
	lastUID    imap.UID
	
	// Circuit breaker for connection failures
	failureCount int
	lastFailure  time.Time
	maxFailures  int
	backoffTime  time.Duration
	
	// Resource management
	ctx        context.Context
	cancel     context.CancelFunc
	isShutdown bool
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
func NewClient(email, username, password string, login *bridgev2.UserLogin, log *zerolog.Logger) (*Client, error) {
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
	
	return &Client{
		Email:        email,
		Host:         host,
		Port:         port,
		Username:     username,
		Password:     password, // Never logged
		TLS:          useTLS,
		login:        login,
		log:          log,
		stopIdle:     make(chan struct{}),
		reconnect:    make(chan struct{}),
		// Circuit breaker settings
		maxFailures:  5,
		backoffTime:  time.Minute * 2,
		// Context management
		ctx:          ctx,
		cancel:       cancel,
	}, nil
}

// Connect establishes connection to the IMAP server
func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
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

	// Create IMAP client
	c.client = imapclient.New(conn, &imapclient.Options{
		DebugWriter: nil, // Debug logging disabled for production
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
		close(c.stopIdle)
		c.stopIdle = make(chan struct{})
		c.idling = false
	}

	// Close connection
	if c.client != nil {
		if err := c.client.Logout().Wait(); err != nil {
			c.log.Warn().Err(err).Msg("Error during IMAP logout")
		}
		c.client.Close()
		c.client = nil
	}

	c.connected = false
	c.log.Info().Msg("Disconnected from IMAP server")
	
	return nil
}

// StartIDLE begins IMAP IDLE monitoring for real-time email delivery
func (c *Client) StartIDLE() error {
	c.mu.Lock()
	if c.idling {
		c.mu.Unlock()
		return fmt.Errorf("IDLE already running")
	}
	if !c.connected {
		c.mu.Unlock()
		return fmt.Errorf("not connected to IMAP server")
	}
	c.idling = true
	c.mu.Unlock()

	c.log.Info().Msg("Starting IMAP IDLE monitoring")

	// Select INBOX - this will reset any stale connection state
	if _, err := c.client.Select("INBOX", nil).Wait(); err != nil {
		c.mu.Lock()
		c.idling = false
		c.mu.Unlock()
		return fmt.Errorf("failed to select INBOX: %w", err)
	}

	// Test IDLE capability before starting the loop
	// This will fail immediately if server thinks IDLE is already running
	testIdleCmd, err := c.client.Idle()
	if err != nil {
		c.mu.Lock()
		c.idling = false
		c.mu.Unlock()
		
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
	}

	// Start IDLE monitoring in goroutine
	go c.idleLoop()

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
	
	c.stopIdle = make(chan struct{})
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
			c.log.Info().Msg("Reconnecting IMAP client")
			if err := c.reconnectClient(); err != nil {
				c.log.Error().Err(err).Msg("Failed to reconnect")
				// Wait before retrying
				time.Sleep(30 * time.Second)
				continue
			}
		default:
			if err := c.runIDLE(); err != nil {
				c.log.Error().Err(err).Msg("IDLE failed, will reconnect")
				// Trigger reconnection
				select {
				case c.reconnect <- struct{}{}:
				default:
				}
				time.Sleep(5 * time.Second)
			}
		}
	}
}

// runIDLE executes a single IDLE session
func (c *Client) runIDLE() error {
	c.log.Debug().Msg("Starting IDLE session")

	// Create IDLE command
	idleCmd, err := c.client.Idle()
	if err != nil {
		// If IDLE fails due to "already running", this indicates server-side state desync
		// Force a reconnection to clean up the connection state
		if strings.Contains(err.Error(), "already running") || strings.Contains(err.Error(), "IDLE already") {
			c.log.Warn().Err(err).Msg("IDLE already running on server - forcing reconnection to reset state")
			// Signal reconnection needed
			select {
			case c.reconnect <- struct{}{}:
			default:
			}
			return fmt.Errorf("IDLE state desync detected, reconnection triggered: %w", err)
		}
		return fmt.Errorf("failed to start IDLE: %w", err)
	}

	// Wait for updates or timeout
	idleDone := make(chan error, 1)
	go func() {
		// IDLE for up to 29 minutes (most servers timeout at 30)
		time.Sleep(29 * time.Minute)
		idleDone <- idleCmd.Close()
	}()

	// Monitor for updates - simplified version for now
	for {
		select {
		case <-c.stopIdle:
			idleCmd.Close()
			return nil
			
		case err := <-idleDone:
			if err != nil {
				return fmt.Errorf("IDLE session ended with error: %w", err)
			}
			// IDLE ended normally (timeout), check for new messages
			if err := c.checkNewMessages(); err != nil {
				c.log.Error().Err(err).Msg("Error checking new messages")
			}
			return nil
		}
	}
}

// checkNewMessages fetches and processes new messages
func (c *Client) checkNewMessages() error {
	c.log.Info().Msg("Starting manual sync - checking for new messages")
	
	// Get current lastUID safely
	c.mu.RLock()
	currentLastUID := c.lastUID
	c.mu.RUnlock()
	
	// Use SEARCH command to find new messages without affecting IDLE state
	c.log.Info().Uint32("from_uid", uint32(currentLastUID+1)).Uint32("current_last_uid", uint32(currentLastUID)).Msg("Searching for new messages")
	
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
		// Get the current highest UID to mark as our starting point
		statusCmd := c.client.Status("INBOX", &imap.StatusOptions{
			UIDNext: true,
		})
		statusData, err := statusCmd.Wait()
		if err != nil {
			c.log.Error().Err(err).Msg("Failed to get INBOX status")
			return fmt.Errorf("failed to get INBOX status: %w", err)
		}
		
		// Set lastUID to current highest UID so we only sync NEW messages from now on
		currentHighestUID := statusData.UIDNext - 1
		c.mu.Lock()
		c.lastUID = currentHighestUID
		c.mu.Unlock()
		
		c.log.Info().Uint32("last_uid", uint32(currentHighestUID)).Msg("First sync complete - bridge is now up-to-date, will only sync NEW messages")
		return nil // No need to search for existing messages
	}
	
	c.log.Debug().Interface("search_criteria", searchCriteria).Msg("Starting IMAP UID search")
	
	// Create search command with timeout handling
	searchCmd := c.client.UIDSearch(&searchCriteria, nil)
	var newUIDs []imap.UID
	
	// Wait for search results with timeout
	c.log.Debug().Msg("Waiting for IMAP search results")
	
	// Create a timeout channel for the search operation
	searchDone := make(chan error, 1)
	go func() {
		_, err := searchCmd.Wait()
		searchDone <- err
	}()
	
	// Wait with timeout
	select {
	case err := <-searchDone:
		if err != nil {
			c.log.Error().Err(err).Msg("Failed to search for new messages")
			return fmt.Errorf("failed to search for new messages: %w", err)
		}
	case <-time.After(30 * time.Second):
		c.log.Error().Msg("IMAP search timed out after 30 seconds")
		return fmt.Errorf("IMAP search timed out")
	}
	
	c.log.Debug().Msg("IMAP search completed")
	
	// Get search results
	searchResult, err := searchCmd.Wait()
	if err != nil {
		c.log.Error().Err(err).Msg("Failed to get search results")
		return fmt.Errorf("failed to get search results: %w", err)
	}
	
	// Get the UIDs from search results
	newUIDs = searchResult.AllUIDs()
	
	if len(newUIDs) == 0 {
		c.log.Info().Msg("No new messages found")
		return nil
	}
	
	c.log.Info().Int("count", len(newUIDs)).Msg("Found new messages")
	
	// Process the new messages
	for _, uid := range newUIDs {
		if err := c.processMessage(context.Background(), uid); err != nil {
			c.log.Error().Err(err).Uint32("uid", uint32(uid)).Msg("Failed to process message")
			// Continue processing other messages even if one fails
		}
	}
	
	// Update lastUID to the highest UID we processed
	if len(newUIDs) > 0 {
		// Find the highest UID
		highestUID := newUIDs[0]
		for _, uid := range newUIDs[1:] {
			if uid > highestUID {
				highestUID = uid
			}
		}
		
		c.mu.Lock()
		c.lastUID = highestUID
		c.mu.Unlock()
		c.log.Info().Uint32("new_last_uid", uint32(highestUID)).Msg("Updated lastUID after processing messages")
	}
	
	c.log.Info().Msg("Sync completed successfully")
	return nil
}

// SetProcessor sets the email processor for this client
func (c *Client) SetProcessor(processor *email.Processor) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.processor = processor
}

// processNewMessages handles new email messages by fetching and processing them
func (c *Client) processNewMessages(fromUID, toUID imap.UID) {
	if c.processor == nil {
		c.log.Warn().Msg("No email processor set, skipping message processing")
		return
	}

	c.log.Info().Uint32("from", uint32(fromUID)).Uint32("to", uint32(toUID)).Msg("Processing new messages")

	ctx := context.Background()

	// Fetch messages in the UID range
	for uid := fromUID; uid <= toUID; uid++ {
		if err := c.processMessage(ctx, uid); err != nil {
			c.log.Error().Err(err).Uint32("uid", uint32(uid)).Msg("Failed to process message")
		}
	}
}

// processMessage fetches and processes a single email message
func (c *Client) processMessage(ctx context.Context, uid imap.UID) error {
	c.log.Debug().Uint32("uid", uint32(uid)).Msg("Fetching message")

	// Fetch message with headers and body
	fetchOptions := &imap.FetchOptions{
		Envelope: true,
		BodyStructure: &imap.FetchItemBodyStructure{},
		Flags: true,
		UID: true,
	}

	// Also fetch headers and text content
	fetchOptions.BodySection = []*imap.FetchItemBodySection{
		{Specifier: imap.PartSpecifierHeader},
		{Specifier: imap.PartSpecifierText},
	}

	// Create UID set and execute fetch command
	uidSet := imap.UIDSetNum(uid)
	fetchCmd := c.client.Fetch(uidSet, fetchOptions)
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

		// Process the message using the email processor
		emailMessage, err := c.processor.ProcessIMAPMessage(ctx, msg, c.login)
		if err != nil {
			return fmt.Errorf("failed to process IMAP message: %w", err)
		}

		// Convert to Matrix event and queue it
		matrixEvent := c.processor.ToMatrixEvent(ctx, emailMessage, c.login)

		// Queue the event with the bridge framework
		if !c.login.QueueRemoteEvent(matrixEvent).Success {
			c.log.Error().Str("message_id", string(emailMessage.MessageID)).Msg("Failed to queue remote event")
		} else {
			c.log.Info().Str("message_id", string(emailMessage.MessageID)).Str("subject", emailMessage.Subject).Msg("Successfully queued email message")
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
	c.mu.Unlock()
	
	// Disconnect first
	c.Disconnect()
	
	// Calculate exponential backoff (min 5s, max 5min)
	backoffDuration := time.Duration(c.failureCount+1) * 5 * time.Second
	if backoffDuration > 5*time.Minute {
		backoffDuration = 5 * time.Minute
	}
	
	c.log.Info().Dur("backoff", backoffDuration).Int("failure_count", c.failureCount).Msg("Waiting before reconnection attempt")
	time.Sleep(backoffDuration)
	
	// Reconnect
	if err := c.Connect(); err != nil {
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

// CheckNewMessages is a public method to manually check for new messages
// This can be called during periodic sync or when IDLE is not running
func (c *Client) CheckNewMessages() error {
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
		// Run the sync
		err := c.checkNewMessages()
		
		// Restart IDLE
		c.log.Info().Msg("Restarting IDLE after manual sync")
		if restartErr := c.StartIDLE(); restartErr != nil {
			c.log.Error().Err(restartErr).Msg("Failed to restart IDLE after sync")
			// Return the original sync error if sync failed, otherwise the restart error
			if err != nil {
				return err
			}
			return restartErr
		}
		
		return err
	}
	
	// IDLE not running, safe to check messages directly
	return c.checkNewMessages()
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
		return fmt.Errorf("NOOP command failed: %w", err)
	}
	
	c.log.Debug().Msg("Connection test successful (NOOP command completed)")
	return nil
}

// resetConnection forces a complete disconnection and reconnection to clear server-side state
func (c *Client) resetConnection() error {
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
	
	// Establish fresh connection
	if err := c.Connect(); err != nil {
		return fmt.Errorf("failed to reconnect after reset: %w", err)
	}
	
	// Try IDLE again on the fresh connection
	return c.StartIDLE()
}
