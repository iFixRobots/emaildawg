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
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}

	// Create IMAP client
	c.client = imapclient.New(conn, &imapclient.Options{
		DebugWriter: nil, // Debug logging disabled for production
	})

	// Authenticate
	if err := c.client.Login(c.Username, c.Password).Wait(); err != nil {
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

	// Select INBOX
	if _, err := c.client.Select("INBOX", nil).Wait(); err != nil {
		return fmt.Errorf("failed to select INBOX: %w", err)
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
	// Get current mailbox status
	status, err := c.client.Status("INBOX", &imap.StatusOptions{
		NumMessages: true,
		UIDNext:     true,
	}).Wait()
	if err != nil {
		return fmt.Errorf("failed to get mailbox status: %w", err)
	}

	// Handle potential nil values
	var numMessages uint32
	var uidNext imap.UID
	if status.NumMessages != nil {
		numMessages = *status.NumMessages
	}
	uidNext = status.UIDNext

	c.log.Debug().Uint32("total_messages", numMessages).Uint32("uid_next", uint32(uidNext)).Msg("Mailbox status")

	// If we haven't set lastUID yet, set it to current UIDNext to avoid processing old messages
	c.mu.Lock()
	if c.lastUID == 0 {
		if uidNext > 0 {
			c.lastUID = uidNext - 1
		}
		c.mu.Unlock()
		c.log.Info().Uint32("last_uid", uint32(c.lastUID)).Msg("Initialized lastUID, will only process new messages")
		return nil
	}
	currentLastUID := c.lastUID
	c.mu.Unlock()

	// Fetch messages newer than lastUID
	if uidNext <= currentLastUID+1 {
		c.log.Debug().Msg("No new messages to process")
		return nil
	}

	c.log.Info().Uint32("from_uid", uint32(currentLastUID+1)).Uint32("to_uid", uint32(uidNext-1)).Msg("Processing new messages")

	// Process new messages
	c.processNewMessages(currentLastUID+1, uidNext-1)

	// Update lastUID
	c.mu.Lock()
	c.lastUID = uidNext - 1
	c.mu.Unlock()

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
	c.mu.RUnlock()
	
	if !connected {
		return fmt.Errorf("IMAP client not connected")
	}
	
	return c.checkNewMessages()
}
