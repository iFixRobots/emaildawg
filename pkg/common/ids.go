package common

import (
	"strings"
	"maunium.net/go/mautrix/bridgev2/networkid"
)

// EmailToGhostID converts an email address to a Matrix ghost user ID in a single, canonical place.
// Scheme: "email:" + <raw-address>
func EmailToGhostID(email string) networkid.UserID {
	addr := strings.TrimSpace(email)
	return networkid.UserID("email:" + addr)
}
