package common

import (
	"fmt"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"strings"
)

// EmailToGhostID converts an email address to a Matrix ghost user ID in a single, canonical place.
// Scheme: "email:" + <raw-address>
func EmailToGhostID(email string) networkid.UserID {
	addr := strings.TrimSpace(email)
	return networkid.UserID("email:" + addr)
}

// RecoverToError is a common panic recovery utility that converts panics to errors.
// Use in defer statements to catch panics and return them as errors through a channel.
// Safe against nil channels, closed channels, and preserves error wrapping.
func RecoverToError(errCh chan<- error) {
	if r := recover(); r != nil {
		var err error

		// Preserve original error if the panic value is already an error
		if panicErr, ok := r.(error); ok {
			err = fmt.Errorf("panic recovered: %w", panicErr)
		} else {
			err = fmt.Errorf("panic recovered: %v", r)
		}

		// Safe send - non-blocking to prevent deadlocks and handle closed/nil channels
		if errCh != nil {
			select {
			case errCh <- err:
				// Successfully sent
			default:
				// Channel full, closed, or nil - don't block
			}
		}
	}
}

// RecoverToString is a panic recovery utility that converts panics to string messages.
// Must be called directly in a defer statement with a callback to collect the message.
// Example: defer RecoverToString("operation", func(msg string) { if msg != "" { failures = append(failures, msg) } })
func RecoverToString(operation string, sink func(string)) {
	if r := recover(); r != nil {
		msg := fmt.Sprintf("%s: panic %v", operation, r)
		if sink != nil {
			sink(msg)
		}
	}
}
