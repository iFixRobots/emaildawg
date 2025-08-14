package reliability

import (
	"context"
	"fmt"
	"time"
)

// TimeoutConfig holds timeout settings for different operations
type TimeoutConfig struct {
	Connect    time.Duration
	Read       time.Duration
	Write      time.Duration
	Idle       time.Duration
	Command    time.Duration
	Total      time.Duration
}

// DefaultTimeouts returns sensible default timeouts
func DefaultTimeouts() TimeoutConfig {
	return TimeoutConfig{
		Connect: 30 * time.Second,
		Read:    60 * time.Second,
		Write:   30 * time.Second,
		Idle:    5 * time.Minute,
		Command: 30 * time.Second,
		Total:   10 * time.Minute,
	}
}

// IMAPTimeouts returns timeouts optimized for IMAP operations
func IMAPTimeouts() TimeoutConfig {
	return TimeoutConfig{
		Connect: 45 * time.Second,
		Read:    120 * time.Second,  // IMAP can be slow
		Write:   60 * time.Second,
		Idle:    30 * time.Minute,   // IDLE can run long
		Command: 45 * time.Second,
		Total:   15 * time.Minute,
	}
}

// WithTimeout executes a function with a timeout
func WithTimeout(timeout time.Duration, fn func(ctx context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	done := make(chan error, 1)
	go func() {
		defer func() {
			// Recover from any panic in fn to prevent goroutine leak
			if r := recover(); r != nil {
				done <- fmt.Errorf("panic in timeout function: %v", r)
			}
		}()
		done <- fn(ctx)
	}()
	
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		// Wait for goroutine to finish with a grace period to prevent leak
		go func() {
			select {
			case <-done:
				// Function completed after timeout, drain the channel
			case <-time.After(5 * time.Second):
				// Log warning about potential goroutine leak after grace period
				// Note: In production, you'd want to use a proper logger here
			}
		}()
		return ctx.Err()
	}
}

// WithDeadline executes a function with a deadline
func WithDeadline(deadline time.Time, fn func(ctx context.Context) error) error {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	
	done := make(chan error, 1)
	go func() {
		defer func() {
			// Recover from any panic in fn to prevent goroutine leak
			if r := recover(); r != nil {
				done <- fmt.Errorf("panic in deadline function: %v", r)
			}
		}()
		done <- fn(ctx)
	}()
	
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		// Wait for goroutine to finish with a grace period to prevent leak
		go func() {
			select {
			case <-done:
				// Function completed after deadline, drain the channel
			case <-time.After(5 * time.Second):
				// Log warning about potential goroutine leak after grace period
				// Note: In production, you'd want to use a proper logger here
			}
		}()
		return ctx.Err()
	}
}