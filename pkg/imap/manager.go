package imap

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/status"

	"github.com/iFixRobots/emaildawg/pkg/email"
)

// Manager handles multiple IMAP clients for different email accounts
type Manager struct {
	bridge    *bridgev2.Bridge
	log       *zerolog.Logger
	processor *email.Processor

	// Sanitization
	sanitized bool
	secret    string
	
	// Map of userID+email -> IMAP client
	clients map[string]*Client
	mu      sync.RWMutex
	
	// Watchdog control
	watchdogInterval time.Duration

	// Last known state per client key to suppress duplicate state spam
	lastState map[string]status.BridgeStateEvent
}

// NewManager creates a new IMAP manager
func NewManager(bridge *bridgev2.Bridge, log *zerolog.Logger, sanitized bool, secret string) *Manager {
	return &Manager{
		bridge:   bridge,
		log:     log,
		sanitized: sanitized,
		secret:   secret,
		clients: make(map[string]*Client),
		watchdogInterval: 60 * time.Second,
		lastState: make(map[string]status.BridgeStateEvent),
	}
}

// SetProcessor sets the email processor for all current and future clients
func (m *Manager) SetProcessor(processor *email.Processor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.processor = processor
	
	// Set processor on all existing clients
	for _, client := range m.clients {
		client.SetProcessor(processor)
	}
}

// AddAccount adds and starts monitoring an email account
func (m *Manager) AddAccount(login *bridgev2.UserLogin, email, username, password string) error {
	clientKey := m.getClientKey(login.UserMXID.String(), email)
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Check if already exists
	if _, exists := m.clients[clientKey]; exists {
		return fmt.Errorf("account %s already exists for user %s", email, login.UserMXID)
	}
	
	// Create new IMAP client
	logger := m.log.With().
		Str("user", login.UserMXID.String()).
		Str("email", email).Logger()
client, err := NewClient(email, username, password, login, &logger, m.sanitized, m.secret, 180, 25, 3, nil)
	if err != nil {
		return fmt.Errorf("failed to create IMAP client: %w", err)
	}

	// Set the email processor on the client
	if m.processor != nil {
		client.SetProcessor(m.processor)
	}
	
	// Connect to IMAP server
	if err := client.Connect(); err != nil {
		return fmt.Errorf("failed to connect to IMAP server: %w", err)
	}
	
	// Start IDLE monitoring
	if err := client.StartIDLE(); err != nil {
		client.Disconnect() // Clean up on failure
		return fmt.Errorf("failed to start IDLE monitoring: %w", err)
	}
	
// Store client
m.clients[clientKey] = client

// Start watchdog for this client
m.startWatchdog(login.UserMXID.String(), email, client)

m.log.Info().Str("user", login.UserMXID.String()).Str("email", email).Msg("Added and started monitoring email account")

return nil
}

// RemoveAccount removes and stops monitoring an email account
func (m *Manager) RemoveAccount(userMXID string, email string) error {
	clientKey := m.getClientKey(userMXID, email)
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	client, exists := m.clients[clientKey]
	if !exists {
		return fmt.Errorf("account %s not found for user %s", email, userMXID)
	}
	
	// Stop IDLE and disconnect
	client.StopIDLE()
	client.Disconnect()
	
	// Remove from map
	delete(m.clients, clientKey)
	
	m.log.Info().Str("user", userMXID).Str("email", email).Msg("Removed email account")
	
	return nil
}

// GetAccount returns the IMAP client for a specific email account
func (m *Manager) GetAccount(userMXID, email string) (*Client, error) {
	clientKey := m.getClientKey(userMXID, email)
	
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	client, exists := m.clients[clientKey]
	if !exists {
		return nil, fmt.Errorf("account %s not found for user %s", email, userMXID)
	}
	
	return client, nil
}

// ListAccounts returns all email accounts for a user
func (m *Manager) ListAccounts(userMXID string) []*Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	var accounts []*Client
	prefix := userMXID + ":"
	
	for key, client := range m.clients {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			accounts = append(accounts, client)
		}
	}
	
	return accounts
}

// GetAccountStatus returns status information for a user's accounts
func (m *Manager) GetAccountStatus(userMXID string) []AccountStatus {
	accounts := m.ListAccounts(userMXID)
	status := make([]AccountStatus, len(accounts))
	
	for i, client := range accounts {
		status[i] = AccountStatus{
			Email:     client.Email,
			Host:      client.Host,
			Port:      client.Port,
			Connected: client.IsConnected(),
			IDLEActive: client.IsIDLERunning(),
		}
	}
	
	return status
}

// StopAll stops monitoring for all accounts
func (m *Manager) StopAll() {
	// Copy clients under lock, then stop outside lock to avoid blocking other operations
	m.mu.Lock()
	clients := make([]*Client, 0, len(m.clients))
	for _, c := range m.clients {
		clients = append(clients, c)
	}
	// Clear immediately so new operations see empty set
	m.clients = make(map[string]*Client)
	m.mu.Unlock()
	
	for _, client := range clients {
		client.StopIDLE()
		_ = client.Disconnect()
	}
	
	m.log.Info().Msg("Stopped all IMAP clients")
}

// RegisterClient registers an existing IMAP client with the manager for status reporting
func (m *Manager) RegisterClient(userMXID, email string, client *Client) {
	clientKey := m.getClientKey(userMXID, email)
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Store the client for status reporting
	m.clients[clientKey] = client
	// Start watchdog for this client
	m.startWatchdog(userMXID, email, client)
	
	m.log.Debug().Str("user", userMXID).Str("email", email).Msg("Registered IMAP client for status reporting")
}

// getClientKey generates a unique key for storing clients
func (m *Manager) getClientKey(userMXID, email string) string {
return fmt.Sprintf("%s:%s", userMXID, email)
}

// Legacy function removed - state coordinator handles bridge state now

// startWatchdog launches a periodic health check for a client
func (m *Manager) startWatchdog(userMXID, email string, client *Client) {
	interval := m.watchdogInterval
	if interval == 0 {
		interval = 60 * time.Second
	}
	logger := m.log.With().Str("user", userMXID).Str("email", email).Str("component", "imap_watchdog").Logger()
	go func() {
		Ticker := time.NewTicker(interval)
		defer Ticker.Stop()
		for range Ticker.C {
			// Snapshot connected state
			if !client.IsConnected() {
				// Check if the client is already reconnecting to avoid interference
				if client.IsReconnecting() {
					logger.Debug().Msg("Client already reconnecting, watchdog waiting")
					continue
				}
				
				// Attempt to bring the client back online even if it's currently disconnected
				logger.Warn().Msg("Client disconnected, attempting reconnect from watchdog")
				if recErr := client.Reconnect(); recErr != nil {
					// Check if error indicates concurrent operation in progress
					if strings.Contains(recErr.Error(), "already in progress") {
						logger.Debug().Msg("Reconnect already in progress, watchdog backing off")
						continue
					}
					logger.Error().Err(recErr).Msg("Reconnect failed from watchdog while disconnected")
					continue
				}
				// Only try to start IDLE if not already running
				if !client.IsIDLERunning() {
					if err := client.StartIDLE(); err != nil {
						if !strings.Contains(err.Error(), "already running") {
							logger.Warn().Err(err).Msg("Reconnected but failed to start IDLE")
						}
					} else if client.login != nil {
						// State coordinator handles bridge state now
					}
				}
				continue
			}
			if err := client.TestConnection(); err != nil {
				logger.Warn().Err(err).Msg("Health probe failed, triggering reconnect")
				if recErr := client.Reconnect(); recErr != nil {
					// Check if error indicates concurrent operation in progress
					if strings.Contains(recErr.Error(), "already in progress") {
						logger.Debug().Msg("Reconnect already in progress, watchdog backing off")
						continue
					}
					logger.Error().Err(recErr).Msg("Reconnect failed from watchdog")
					continue
				}
				// Only restart IDLE if not already running
				if !client.IsIDLERunning() {
					if err := client.StartIDLE(); err != nil {
						if !strings.Contains(err.Error(), "already running") {
							logger.Warn().Err(err).Msg("Reconnected but failed to start IDLE")
						}
					}
				}
			}
		}
	}()
}

// AccountStatus represents the status of an email account
type AccountStatus struct {
	Email      string `json:"email"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Connected  bool   `json:"connected"`
	IDLEActive bool   `json:"idle_active"`
}
