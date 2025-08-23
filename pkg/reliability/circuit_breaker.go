package reliability

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrCircuitBreakerOpen = errors.New("circuit breaker is open")
	ErrTooManyRequests    = errors.New("too many requests")
)

// StateChangeCallback is called when circuit breaker state changes
type StateChangeCallback func(oldState, newState CircuitBreakerState)

// CircuitBreakerState represents the state of the circuit breaker
type CircuitBreakerState int

const (
	StateClosed CircuitBreakerState = iota
	StateHalfOpen
	StateOpen
)

// String returns the string representation of CircuitBreakerState
func (s CircuitBreakerState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateHalfOpen:
		return "half_open"
	case StateOpen:
		return "open"
	default:
		return "unknown"
	}
}

// CircuitBreaker implements the circuit breaker pattern for fault tolerance
type CircuitBreaker struct {
	mu                   sync.RWMutex
	maxFailures          int
	timeout              time.Duration
	failures             int
	lastFailureTime      time.Time
	state                CircuitBreakerState
	// Half-open state management
	maxHalfOpenRequests  int
	halfOpenRequests     int32 // atomic counter for concurrent requests in half-open state
	// State change notification
	stateChangeCallback StateChangeCallback // Optional callback for state changes
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(maxFailures int, timeout time.Duration) (*CircuitBreaker, error) {
	// Validate input parameters
	if maxFailures <= 0 {
		return nil, errors.New("maxFailures must be greater than 0")
	}
	if timeout <= 0 {
		return nil, errors.New("timeout must be greater than 0")
	}
	
	return &CircuitBreaker{
		maxFailures:         maxFailures,
		timeout:             timeout,
		state:               StateClosed,
		maxHalfOpenRequests: 1, // Allow only 1 test request in half-open by default
	}, nil
}

// SetStateChangeCallback sets a callback to be invoked when state changes
func (cb *CircuitBreaker) SetStateChangeCallback(callback StateChangeCallback) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.stateChangeCallback = callback
}

// Execute runs the given function through the circuit breaker
func (cb *CircuitBreaker) Execute(fn func() error) error {
	// Check state and handle counter increment atomically
	shouldDecrement, err := cb.checkStateAndIncrement()
	if err != nil {
		return err
	}
	
	// Ensure we decrement if we incremented, regardless of state changes
	defer func() {
		if shouldDecrement {
			atomic.AddInt32(&cb.halfOpenRequests, -1)
		}
	}()
	
	// Execute function
	err = fn()
	
	cb.recordResult(err)
	return err
}

// checkStateAndIncrement checks state and increments counter atomically, returns (shouldDecrement, error)
func (cb *CircuitBreaker) checkStateAndIncrement() (bool, error) {
	// First, quick read-only check
	cb.mu.RLock()
	currentState := cb.state
	lastFailure := cb.lastFailureTime
	cb.mu.RUnlock()

	// Handle state transitions with proper locking
	switch currentState {
	case StateOpen:
		if time.Since(lastFailure) > cb.timeout {
			// Need to transition to half-open - acquire write lock
			cb.mu.Lock()
			// Double-check conditions under write lock
			if cb.state == StateOpen && time.Since(cb.lastFailureTime) > cb.timeout {
				oldState := cb.state
				cb.state = StateHalfOpen
				atomic.StoreInt32(&cb.halfOpenRequests, 0) // Reset counter
				
				// Notify callback of state change outside lock to prevent deadlock
				callback := cb.stateChangeCallback
				cb.mu.Unlock()
				if callback != nil {
					callback(oldState, StateHalfOpen)
				}
				cb.mu.Lock() // Re-acquire for defer unlock
			}
			currentState = cb.state // Update local state
			cb.mu.Unlock()
		}
		
		if currentState == StateOpen {
			return false, ErrCircuitBreakerOpen
		}
		// Fall through to handle StateHalfOpen case if we transitioned
		fallthrough
	case StateHalfOpen:
		// Atomically increment and check limit to prevent race condition
		newRequests := atomic.AddInt32(&cb.halfOpenRequests, 1)
		if newRequests > int32(cb.maxHalfOpenRequests) {
			// Over limit - decrement back and reject
			atomic.AddInt32(&cb.halfOpenRequests, -1)
			return false, ErrTooManyRequests
		}
		return true, nil // We incremented successfully, caller should decrement
	}
	return false, nil
}

// recordResult records the result of the executed function
func (cb *CircuitBreaker) recordResult(err error) {
	cb.mu.Lock()

	oldState := cb.state

	if err == nil {
		// Success: reset failures and close circuit
		cb.failures = 0
		cb.state = StateClosed
	} else {
		// Failure: increment counter and check if we need to open
		cb.failures++
		cb.lastFailureTime = time.Now()

		if cb.failures >= cb.maxFailures {
			cb.state = StateOpen
		}
	}
	
	// Reset half-open counter when transitioning out of half-open state
	if oldState == StateHalfOpen && cb.state != StateHalfOpen {
		atomic.StoreInt32(&cb.halfOpenRequests, 0)
	}

	// Notify callback if state changed - execute outside lock to prevent deadlock
	var callback StateChangeCallback
	var newState CircuitBreakerState
	if oldState != cb.state && cb.stateChangeCallback != nil {
		callback = cb.stateChangeCallback
		newState = cb.state
	}
	cb.mu.Unlock() // Release lock before callback
	
	if callback != nil {
		callback(oldState, newState)
	}
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// GetFailures returns the current failure count
func (cb *CircuitBreaker) GetFailures() int {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.failures
}

// Reset manually resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.state = StateClosed
	// Reset half-open request counter for consistent state
	atomic.StoreInt32(&cb.halfOpenRequests, 0)
}