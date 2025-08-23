package reliability

import (
	"context"
	"crypto/rand"
	"math"
	mathrand "math/rand"
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
	// Validate config parameters to prevent runtime issues
	if config.MaxAttempts <= 0 {
		config.MaxAttempts = 1 // At least one attempt
	}
	if config.InitialDelay <= 0 {
		config.InitialDelay = 100 * time.Millisecond
	}
	if config.MaxDelay <= 0 {
		config.MaxDelay = 30 * time.Second
	}
	if config.BackoffFactor <= 1.0 {
		config.BackoffFactor = 2.0
	}
	// Ensure MaxDelay >= InitialDelay to prevent invalid calculations
	if config.MaxDelay < config.InitialDelay {
		config.MaxDelay = config.InitialDelay
	}
	
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
	// Calculate exponential backoff delay with overflow protection
	var delay float64
	
	// Compute exponent safely
	e := float64(attempt) * math.Log(c.BackoffFactor)
	maxE := math.Log(float64(c.MaxDelay)/float64(c.InitialDelay))
	
	// Check for overflow/overshoot or invalid values
	if math.IsNaN(e) || math.IsInf(e, 0) || e > maxE {
		delay = float64(c.MaxDelay)
	} else {
		// Safe to compute exponential
		multiplier := math.Exp(e)
		if math.IsNaN(multiplier) || math.IsInf(multiplier, 0) {
			delay = float64(c.MaxDelay)
		} else {
			delay = float64(c.InitialDelay) * multiplier
			// Cap at maximum delay
			if delay > float64(c.MaxDelay) {
				delay = float64(c.MaxDelay)
			}
		}
	}
	
	// Add jitter if enabled, ensuring it doesn't exceed MaxDelay
	if c.Jitter {
		// Add cryptographically secure random jitter up to 25% of the delay
		jitterRange := delay * 0.25
		jitter := secureRandFloat64() * jitterRange
		delay += jitter
		
		// Ensure jitter doesn't push us past MaxDelay
		if delay > float64(c.MaxDelay) {
			delay = float64(c.MaxDelay)
		}
	}
	
	// Sanitize NaN/Inf before converting to Duration
	if math.IsNaN(delay) || math.IsInf(delay, 0) || delay < 0 {
		delay = float64(c.MaxDelay)
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
		"operation timed out",
		"temporary failure",
		"network unreachable",
		"host unreachable",
		"no such host",
		"i/o timeout",
		"broken pipe",
		"use of closed network connection",
		"connection lost",
		"server misbehaving",
		"cannot read tag",
		"unexpected eof",
	}
	
	for _, pattern := range retryablePatterns {
		if contains(errStr, pattern) {
			return true
		}
	}
	
	// IMAP-specific transient errors with specific matching to avoid false positives
	imapRetryablePatterns := []string{
		"* bye",                           // Server connection terminated (start of line)
		"no unavailable",                  // IMAP NO response with UNAVAILABLE
		"bad serverbug",                   // IMAP BAD response with SERVERBUG  
		"no contactadmin",                 // IMAP NO response with CONTACTADMIN
		"bad [clientbug]",                 // IMAP BAD response with [CLIENTBUG]
		"server temporarily unavailable",  // Full phrase match
		"temporary failure in name resolution", // DNS issues
		"mailbox unavailable",             // Mailbox locked/busy
	}
	
	// Use more specific matching for IMAP patterns
	for _, pattern := range imapRetryablePatterns {
		if matchesIMAPPattern(errStr, pattern) {
			return true
		}
	}
	
	return false
}

// secureRandFloat64 generates a cryptographically secure random float64 in [0, 1)
func secureRandFloat64() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback to math/rand if crypto/rand fails - rare but possible
		return mathrand.Float64()
	}
	// Convert 8 bytes to uint64, then to float64 in [0, 1)
	u := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	// Use IEEE 754 double precision mantissa (53 bits) for uniform distribution
	return float64(u>>11) / float64(1<<53)
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// matchesIMAPPattern checks if an error string matches IMAP pattern with specific rules
func matchesIMAPPattern(errStr, pattern string) bool {
	errLower := strings.ToLower(errStr)
	patternLower := strings.ToLower(pattern)
	
	// For patterns starting with "* ", match at beginning of line
	if strings.HasPrefix(patternLower, "* ") {
		return strings.HasPrefix(errLower, patternLower) ||
			   strings.Contains(errLower, "\n"+patternLower)
	}
	
	// For patterns with response codes (NO, BAD), ensure word boundaries
	if strings.HasPrefix(patternLower, "no ") || 
	   strings.HasPrefix(patternLower, "bad ") {
		// Match at word boundaries to avoid false positives
		return strings.Contains(errLower, patternLower) &&
			   (strings.HasPrefix(errLower, patternLower) ||
				strings.Contains(errLower, " "+patternLower) ||
				strings.Contains(errLower, "\n"+patternLower))
	}
	
	// For other patterns, use exact phrase matching
	return strings.Contains(errLower, patternLower)
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