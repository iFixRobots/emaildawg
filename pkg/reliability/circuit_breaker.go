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

// CircuitBreakerState represents the state of the circuit breaker
type CircuitBreakerState int

const (
	StateClosed CircuitBreakerState = iota
	StateHalfOpen
	StateOpen
)

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

// Execute runs the given function through the circuit breaker
func (cb *CircuitBreaker) Execute(fn func() error) error {
	if err := cb.checkState(); err != nil {
		return err
	}

	// Track if we're in half-open to decrement counter later
	wasHalfOpen := cb.GetState() == StateHalfOpen
	
	// Execute function
	err := fn()
	
	// Decrement half-open counter if we were in half-open state
	if wasHalfOpen {
		atomic.AddInt32(&cb.halfOpenRequests, -1)
	}
	
	cb.recordResult(err)
	return err
}

// checkState checks if the circuit breaker allows the request
func (cb *CircuitBreaker) checkState() error {
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
				cb.state = StateHalfOpen
				atomic.StoreInt32(&cb.halfOpenRequests, 0) // Reset counter
			}
			currentState = cb.state // Update local state
			cb.mu.Unlock()
		}
		
		if currentState == StateOpen {
			return ErrCircuitBreakerOpen
		}
		// Fall through to handle StateHalfOpen case if we transitioned
		fallthrough
	case StateHalfOpen:
		// Limit concurrent requests in half-open state
		currentRequests := atomic.LoadInt32(&cb.halfOpenRequests)
		if currentRequests >= int32(cb.maxHalfOpenRequests) {
			return ErrTooManyRequests
		}
		// Increment counter atomically
		atomic.AddInt32(&cb.halfOpenRequests, 1)
		return nil
	}
	return nil
}

// recordResult records the result of the executed function
func (cb *CircuitBreaker) recordResult(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

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
}