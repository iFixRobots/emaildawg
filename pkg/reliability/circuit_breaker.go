package reliability

import (
	"errors"
	"sync"
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
	mu              sync.RWMutex
	maxFailures     int
	timeout         time.Duration
	failures        int
	lastFailureTime time.Time
	state           CircuitBreakerState
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(maxFailures int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		maxFailures: maxFailures,
		timeout:     timeout,
		state:       StateClosed,
	}
}

// Execute runs the given function through the circuit breaker
func (cb *CircuitBreaker) Execute(fn func() error) error {
	if err := cb.checkState(); err != nil {
		return err
	}

	err := fn()
	cb.recordResult(err)
	return err
}

// checkState checks if the circuit breaker allows the request
func (cb *CircuitBreaker) checkState() error {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	switch cb.state {
	case StateOpen:
		if time.Since(cb.lastFailureTime) > cb.timeout {
			// Transition to half-open state
			cb.mu.RUnlock()
			cb.mu.Lock()
			if cb.state == StateOpen && time.Since(cb.lastFailureTime) > cb.timeout {
				cb.state = StateHalfOpen
			}
			cb.mu.Unlock()
			cb.mu.RLock()
		}
		if cb.state == StateOpen {
			return ErrCircuitBreakerOpen
		}
	case StateHalfOpen:
		// Allow one request to test if service is back
		return nil
	}
	return nil
}

// recordResult records the result of the executed function
func (cb *CircuitBreaker) recordResult(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

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