package reliability

import (
	"context"
	"math"
	"math/rand"
	"strings"
	"time"
)

// RetryConfig holds configuration for retry operations
type RetryConfig struct {
	MaxAttempts   int
	InitialDelay  time.Duration
	MaxDelay      time.Duration
	BackoffFactor float64
	Jitter        bool
}

// DefaultRetryConfig returns sensible defaults for retry operations
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  100 * time.Millisecond,
		MaxDelay:      30 * time.Second,
		BackoffFactor: 2.0,
		Jitter:        true,
	}
}

// NetworkRetryConfig returns retry config optimized for network operations
func NetworkRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:   5,
		InitialDelay:  250 * time.Millisecond,
		MaxDelay:      60 * time.Second,
		BackoffFactor: 2.0,
		Jitter:        true,
	}
}

// RetryWithBackoff retries a function with exponential backoff and smart error categorization
func RetryWithBackoff(ctx context.Context, config RetryConfig, fn func() error) error {
	var lastErr error
	
	for attempt := 0; attempt < config.MaxAttempts; attempt++ {
		// Execute the function
		err := fn()
		if err == nil {
			return nil // Success
		}
		
		lastErr = err
		
		// Don't retry on the last attempt
		if attempt == config.MaxAttempts-1 {
			break
		}
		
		// Check if this error should be retried based on its category
		if !ShouldRetry(err) {
			// Don't retry authentication or permanent errors
			return err
		}
		
		// Check if context is cancelled
		if ctx.Err() != nil {
			return ctx.Err()
		}
		
		// Calculate delay with exponential backoff
		delay := config.calculateDelay(attempt)
		
		// Wait with context cancellation support
		select {
		case <-time.After(delay):
			// Continue to next attempt
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	
	return lastErr
}

// calculateDelay calculates the delay for the given attempt number
func (c RetryConfig) calculateDelay(attempt int) time.Duration {
	// Calculate exponential backoff delay
	delay := float64(c.InitialDelay) * math.Pow(c.BackoffFactor, float64(attempt))
	
	// Cap at maximum delay
	if delay > float64(c.MaxDelay) {
		delay = float64(c.MaxDelay)
	}
	
	// Add jitter if enabled
	if c.Jitter {
		// Add random jitter up to 25% of the delay
		jitterRange := delay * 0.25
		jitter := rand.Float64() * jitterRange
		delay += jitter
	}
	
	return time.Duration(delay)
}

// IsRetryableError determines if an error should trigger a retry
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}
	
	errStr := err.Error()
	
	// Network-level errors that are usually transient
	retryablePatterns := []string{
		"connection refused",
		"connection reset",
		"connection timeout",
		"timeout",
		"temporary failure",
		"network unreachable",
		"host unreachable",
		"no such host",
		"i/o timeout",
		"broken pipe",
		"use of closed network connection",
		"connection lost",
		"server misbehaving",
	}
	
	for _, pattern := range retryablePatterns {
		if contains(errStr, pattern) {
			return true
		}
	}
	
	// IMAP-specific transient errors
	imapRetryablePatterns := []string{
		"BYE",
		"UNAVAILABLE",
		"SERVERBUG",
		"CONTACTADMIN",
		"BAD [CLIENTBUG]",
		"server temporarily unavailable",
	}
	
	for _, pattern := range imapRetryablePatterns {
		if contains(errStr, pattern) {
			return true
		}
	}
	
	return false
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// ErrorCategory represents different types of errors for handling strategies
type ErrorCategory int

const (
	ErrorTemporary ErrorCategory = iota
	ErrorPermanent 
	ErrorAuthentication
	ErrorNetwork
	ErrorTimeout
)

// CategorizeError determines the category of an error for appropriate handling
func CategorizeError(err error) ErrorCategory {
	if err == nil {
		return ErrorTemporary
	}
	
	errStr := strings.ToLower(err.Error())
	
	// Authentication errors - don't retry these
	authPatterns := []string{
		"authentication failed",
		"login failed", 
		"invalid credentials",
		"bad credentials",
		"access denied",
		"unauthorized",
		"authentication error",
		"authenticationfailed",
	}
	
	for _, pattern := range authPatterns {
		if contains(errStr, pattern) {
			return ErrorAuthentication
		}
	}
	
	// Network errors - usually retryable
	networkPatterns := []string{
		"connection refused",
		"connection reset", 
		"network unreachable",
		"host unreachable",
		"no such host",
		"broken pipe",
		"connection lost",
	}
	
	for _, pattern := range networkPatterns {
		if contains(errStr, pattern) {
			return ErrorNetwork
		}
	}
	
	// Timeout errors - retryable
	timeoutPatterns := []string{
		"timeout",
		"i/o timeout",
		"deadline exceeded",
	}
	
	for _, pattern := range timeoutPatterns {
		if contains(errStr, pattern) {
			return ErrorTimeout
		}
	}
	
	// Server-side permanent errors
	permanentPatterns := []string{
		"no mailbox", 
		"mailbox does not exist",
		"permission denied",
		"quota exceeded",
		"invalid mailbox",
	}
	
	for _, pattern := range permanentPatterns {
		if contains(errStr, pattern) {
			return ErrorPermanent
		}
	}
	
	// Default to temporary for unknown errors
	return ErrorTemporary
}

// ShouldRetry determines if an error should be retried based on its category
func ShouldRetry(err error) bool {
	category := CategorizeError(err)
	
	switch category {
	case ErrorTemporary, ErrorNetwork, ErrorTimeout:
		return true
	case ErrorAuthentication, ErrorPermanent:
		return false
	default:
		return false
	}
}