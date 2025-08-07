package imap

import (
	"fmt"
	"sync"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/bridgev2"

	"go.mau.fi/mautrix-emaildawg/pkg/email"
)

// Manager handles multiple IMAP clients for different email accounts
type Manager struct {
	bridge    bridgev2.Bridge
	log       *zerolog.Logger
	processor *email.Processor
	
	// Map of userID+email -> IMAP client
	clients map[string]*Client
	mu      sync.RWMutex
}

// NewManager creates a new IMAP manager
func NewManager(bridge *bridgev2.Bridge, log *zerolog.Logger) *Manager {
	return &Manager{
		bridge:   *bridge,
		log:     log,
		clients: make(map[string]*Client),
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
	client, err := NewClient(email, username, password, login, &logger)
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
	m.mu.Lock()
	defer m.mu.Unlock()
	
	for _, client := range m.clients {
		client.StopIDLE()
		client.Disconnect()
	}
	
	// Clear all clients
	m.clients = make(map[string]*Client)
	
	m.log.Info().Msg("Stopped all IMAP clients")
}

// getClientKey generates a unique key for storing clients
func (m *Manager) getClientKey(userMXID, email string) string {
	return fmt.Sprintf("%s:%s", userMXID, email)
}

// AccountStatus represents the status of an email account
type AccountStatus struct {
	Email      string `json:"email"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Connected  bool   `json:"connected"`
	IDLEActive bool   `json:"idle_active"`
}
