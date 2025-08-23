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
// WARNING: This function cannot prevent goroutine leaks if fn() doesn't respect context cancellation.
// Callers must ensure fn() checks ctx.Done() periodically to avoid resource leaks.
func runWithCtx(ctx context.Context, logger Logger, fn func(context.Context) error) error {
	done := make(chan error, 1)
	
	go func() {
		defer func() {
			// Recover from any panic in fn to prevent goroutine leak
			if r := recover(); r != nil {
				select {
				case done <- fmt.Errorf("panic in context function: %v", r):
				default:
					// Channel full, receiver already gone - log the panic
					if logger != nil {
						logger.Error("unhandled panic in timed-out function: %v", r)
					}
				}
			}
		}()
		
		// Execute function and send result (non-blocking to prevent goroutine leak)
		err := fn(ctx)
		select {
		case done <- err:
			// Successfully sent result
		default:
			// Channel full (receiver already gone due to timeout)
			// This is expected behavior when function completes after timeout
		}
	}()
	
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		// Context cancelled/timed out - return immediately
		// Note: goroutine may still be running if fn() doesn't respect context
		if logger != nil {
			logger.Warn("function execution cancelled due to timeout - goroutine may still be running if function doesn't check context")
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