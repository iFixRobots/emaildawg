package common

import (
	"fmt"
	"strings"
	"maunium.net/go/mautrix/bridgev2/networkid"
)

// EmailToGhostID converts an email address to a Matrix ghost user ID in a single, canonical place.
// Scheme: "email:" + <raw-address>
func EmailToGhostID(email string) networkid.UserID {
	addr := strings.TrimSpace(email)
	return networkid.UserID("email:" + addr)
}

// RecoverToError is a common panic recovery utility that converts panics to errors.
// Use in defer statements to catch panics and return them as errors through a channel or callback.
func RecoverToError(errCh chan<- error) {
	if r := recover(); r != nil {
		errCh <- fmt.Errorf("panic recovered: %v", r)
	}
}

// RecoverToString is a panic recovery utility that converts panics to string messages.
// Useful for collecting error messages in slices during batch operations.
func RecoverToString(operation string) string {
	if r := recover(); r != nil {
		return fmt.Sprintf("%s: panic %v", operation, r)
	}
	return ""
}
