package reliability

import (
	"context"
	"fmt"
	"time"
)

// Logger interface for timeout operations
type Logger interface {
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

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

// runWithCtx executes a function with context and handles goroutine management
func runWithCtx(ctx context.Context, logger Logger, fn func(context.Context) error) error {
	done := make(chan error, 1)
	go func() {
		defer func() {
			// Recover from any panic in fn to prevent goroutine leak
			if r := recover(); r != nil {
				done <- fmt.Errorf("panic in context function: %v", r)
			}
		}()
		done <- fn(ctx)
	}()
	
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		// Non-blocking drain of done channel
		select {
		case <-done:
			// Function completed after context cancellation, no leak
		default:
			// Function hasn't finished - potential goroutine leak
			if logger != nil {
				logger.Warn("potential goroutine leak: function did not complete before context cancellation")
			}
		}
		return ctx.Err()
	}
}

// WithTimeout executes a function with a timeout
func WithTimeout(parentCtx context.Context, timeout time.Duration, logger Logger, fn func(ctx context.Context) error) error {
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()
	return runWithCtx(ctx, logger, fn)
}

// WithDeadline executes a function with a deadline  
func WithDeadline(parentCtx context.Context, deadline time.Time, logger Logger, fn func(ctx context.Context) error) error {
	ctx, cancel := context.WithDeadline(parentCtx, deadline)
	defer cancel()
	return runWithCtx(ctx, logger, fn)
}