package connector

import (
	"strings"

	"github.com/rs/zerolog"
	"github.com/iFixRobots/emaildawg/pkg/email"
)

// StubThreadMetadataResolver is a placeholder implementation that currently
// just logs lookups and returns no match. In future, this can consult bridgev2
// metadata (e.g., portal/message tables) to resolve message IDs to thread IDs.

type StubThreadMetadataResolver struct {
	Log *zerolog.Logger
}

var _ email.ThreadMetadataResolver = (*StubThreadMetadataResolver)(nil)

func (r *StubThreadMetadataResolver) ResolveThreadID(receiver, messageID string) (string, bool) {
	if r == nil || r.Log == nil {
		return "", false
	}
	// Avoid logging empty or obviously invalid IDs
	mid := strings.TrimSpace(messageID)
	if mid == "" {
		return "", false
	}
	r.Log.Debug().Str("receiver", receiver).Str("message_id", mid).Msg("Stub resolver: no mapping for message_id")
	return "", false
}

