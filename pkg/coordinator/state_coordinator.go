package coordinator

import (
	"sync"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/status"
)

// Error codes used by the state coordinator
var (
	EmailConnectionFailed = status.BridgeStateErrorCode("E-EMAIL-002")
	EmailIdleFailed       = status.BridgeStateErrorCode("E-EMAIL-003")
	EmailCircuitOpen      = status.BridgeStateErrorCode("E-EMAIL-007")
)

// ConnectionEvent represents events about connection state changes
type ConnectionEvent struct {
	Component string // "inbox", "sent", "circuit_breaker"
	Event     EventType
	Connected bool
	Error     status.BridgeStateErrorCode
	Metadata  map[string]any
	Timestamp time.Time
}

// EventType defines the types of events the coordinator can receive
type EventType string

const (
	// Connection lifecycle events
	EventConnectionStarted     EventType = "connection_started"
	EventConnectionEstablished EventType = "connection_established"
	EventConnectionLost        EventType = "connection_lost"
	EventConnectionClosed      EventType = "connection_closed"

	// IDLE specific events
	EventIdleStarted   EventType = "idle_started"
	EventIdleFailed    EventType = "idle_failed"
	EventIdleRecovered EventType = "idle_recovered"

	// Circuit breaker events
	EventCircuitOpened   EventType = "circuit_opened"
	EventCircuitClosed   EventType = "circuit_closed"
	EventCircuitHalfOpen EventType = "circuit_half_open"

	// Health monitoring events
	EventHealthCheckPassed EventType = "health_check_passed"
	EventHealthCheckFailed EventType = "health_check_failed"

	// Authentication events
	EventAuthSuccess EventType = "auth_success"
	EventAuthFailure EventType = "auth_failure"
)

// ConnectionState tracks the state of individual connections
type ConnectionState struct {
	Connected    bool
	IdleRunning  bool
	LastEvent    EventType
	LastError    status.BridgeStateErrorCode
	LastUpdate   time.Time
	FailureCount int
}

// StateCoordinator centralizes all bridge state management
type StateCoordinator struct {
	mu    sync.RWMutex
	login *bridgev2.UserLogin
	log   *zerolog.Logger

	// Connection states
	inbox        ConnectionState
	sent         ConnectionState
	circuitState string

	// Current bridge state
	currentState status.BridgeStateEvent
	currentError status.BridgeStateErrorCode
	lastSent     time.Time

	// State throttling
	throttleDuration time.Duration
}

// NewStateCoordinator creates a new centralized state coordinator
func NewStateCoordinator(login *bridgev2.UserLogin, log *zerolog.Logger) *StateCoordinator {
	return &StateCoordinator{
		login:            login,
		log:              log,
		circuitState:     "closed",
		currentState:     status.StateStarting,
		throttleDuration: 30 * time.Second, // Reduced from 60s for more responsive updates
	}
}

// ReportEvent processes a connection event and updates bridge state accordingly
func (sc *StateCoordinator) ReportEvent(event ConnectionEvent) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.log.Debug().
		Str("component", event.Component).
		Str("event", string(event.Event)).
		Bool("connected", event.Connected).
		Msg("State coordinator received event")

	// Update component state
	sc.updateComponentState(event)

	// Compute new bridge state
	newState, newError := sc.computeBridgeState()

	// Send bridge state if changed or throttle period expired
	if sc.shouldSendState(newState, newError) {
		sc.sendBridgeState(newState, newError, event.Metadata)
	}
}

// updateComponentState updates the internal state based on the event
func (sc *StateCoordinator) updateComponentState(event ConnectionEvent) {
	now := time.Now()

	switch event.Component {
	case "inbox":
		sc.inbox.LastEvent = event.Event
		sc.inbox.LastUpdate = now
		sc.inbox.LastError = event.Error

		switch event.Event {
		case EventConnectionStarted:
			// Starting connection process
		case EventConnectionEstablished:
			sc.inbox.Connected = true
			sc.inbox.FailureCount = 0
		case EventConnectionLost, EventConnectionClosed:
			sc.inbox.Connected = false
			sc.inbox.FailureCount++
		case EventIdleStarted:
			sc.inbox.IdleRunning = true
		case EventIdleFailed:
			sc.inbox.IdleRunning = false
			sc.inbox.FailureCount++
		case EventIdleRecovered:
			sc.inbox.IdleRunning = true
			sc.inbox.FailureCount = 0
		}

	case "sent":
		sc.sent.LastEvent = event.Event
		sc.sent.LastUpdate = now
		sc.sent.LastError = event.Error

		switch event.Event {
		case EventConnectionStarted:
			// Starting connection process
		case EventConnectionEstablished:
			sc.sent.Connected = true
			sc.sent.FailureCount = 0
		case EventConnectionLost, EventConnectionClosed:
			sc.sent.Connected = false
			sc.sent.FailureCount++
		case EventIdleStarted:
			sc.sent.IdleRunning = true
		case EventIdleFailed:
			sc.sent.IdleRunning = false
			sc.sent.FailureCount++
		case EventIdleRecovered:
			sc.sent.IdleRunning = true
			sc.sent.FailureCount = 0
		}

	case "circuit_breaker":
		switch event.Event {
		case EventCircuitOpened:
			sc.circuitState = "open"
		case EventCircuitClosed:
			sc.circuitState = "closed"
		case EventCircuitHalfOpen:
			sc.circuitState = "half_open"
		}
	}
}

// computeBridgeState determines the overall bridge state based on component states
func (sc *StateCoordinator) computeBridgeState() (status.BridgeStateEvent, status.BridgeStateErrorCode) {
	// Circuit breaker has highest priority
	if sc.circuitState == "open" {
		return status.StateBridgeUnreachable, EmailCircuitOpen
	}

	// No INBOX connection = bridge unreachable
	if !sc.inbox.Connected {
		if sc.inbox.LastError != "" {
			return status.StateBridgeUnreachable, sc.inbox.LastError
		}
		return status.StateBridgeUnreachable, EmailConnectionFailed
	}

	// INBOX connected but IDLE not running = transient disconnect
	if sc.inbox.Connected && !sc.inbox.IdleRunning {
		if sc.inbox.LastError != "" {
			return status.StateTransientDisconnect, sc.inbox.LastError
		}
		return status.StateTransientDisconnect, EmailIdleFailed
	}

	// INBOX fully functional
	if sc.inbox.Connected && sc.inbox.IdleRunning {
		// Sent connection failure is noted but doesn't demote bridge state
		// (INBOX functionality is sufficient for basic operation)
		return status.StateConnected, ""
	}

	// Fallback: starting state
	return status.StateStarting, ""
}

// shouldSendState determines if a new state should be sent
func (sc *StateCoordinator) shouldSendState(newState status.BridgeStateEvent, newError status.BridgeStateErrorCode) bool {
	// Always send if state or error changed
	if newState != sc.currentState || newError != sc.currentError {
		return true
	}

	// Send periodic updates if throttle period expired
	if time.Since(sc.lastSent) > sc.throttleDuration {
		return true
	}

	return false
}

// sendBridgeState sends the computed bridge state
func (sc *StateCoordinator) sendBridgeState(newState status.BridgeStateEvent, newError status.BridgeStateErrorCode, metadata map[string]any) {
	if sc.login == nil {
		return
	}

	// Build info map with connection details
	info := make(map[string]any)
	if metadata != nil {
		for k, v := range metadata {
			info[k] = v
		}
	}

	// Add connection health information
	info["inbox_connected"] = sc.inbox.Connected
	info["inbox_idle_running"] = sc.inbox.IdleRunning
	info["sent_connected"] = sc.sent.Connected
	info["sent_idle_running"] = sc.sent.IdleRunning
	info["circuit_breaker_state"] = sc.circuitState
	info["coordinator_update"] = time.Now().Format(time.RFC3339)

	// Add failure counts for debugging
	if sc.inbox.FailureCount > 0 {
		info["inbox_failure_count"] = sc.inbox.FailureCount
	}
	if sc.sent.FailureCount > 0 {
		info["sent_failure_count"] = sc.sent.FailureCount
	}

	bridgeState := status.BridgeState{
		StateEvent: newState,
		Info:       info,
	}

	if newError != "" {
		bridgeState.Error = newError
	}

	sc.log.Info().
		Str("state", string(newState)).
		Str("error", string(newError)).
		Bool("inbox_connected", sc.inbox.Connected).
		Bool("sent_connected", sc.sent.Connected).
		Msg("State coordinator sending bridge state")

	sc.login.BridgeState.Send(bridgeState)

	// Update tracking
	sc.currentState = newState
	sc.currentError = newError
	sc.lastSent = time.Now()
}

// ReportSimpleEvent provides a simple interface for IMAP client to report events
// This method matches the StateCoordinator interface defined in the IMAP package
func (sc *StateCoordinator) ReportSimpleEvent(component string, event string, connected bool, err status.BridgeStateErrorCode, metadata map[string]any) {
	// Convert to internal event structure
	connectionEvent := ConnectionEvent{
		Component: component,
		Event:     EventType(event),
		Connected: connected,
		Error:     err,
		Metadata:  metadata,
		Timestamp: time.Now(),
	}

	// Call the main ReportEvent method
	sc.ReportEvent(connectionEvent)
}

// GetConnectionStates returns the current connection states (for debugging/monitoring)
func (sc *StateCoordinator) GetConnectionStates() (inbox, sent ConnectionState, circuit string) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.inbox, sc.sent, sc.circuitState
}
