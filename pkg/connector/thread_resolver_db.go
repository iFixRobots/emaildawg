package connector

import (
	"context"
	"strings"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/bridgev2"
)

// DBThreadMetadataResolver attempts to resolve an email Message-ID to a thread/portal
// by looking up previously bridged messages in the bridgev2 database.
// It is best-effort: if the schema doesn't match, it returns no match without error.
//
// Expected idea: bridge stores remote messages keyed by network and remote ID (we use
// the raw Message-ID as the RemoteMessage.GetID). Those rows should contain the
// portal/room (thread) identifier the message was sent to.
//
// This resolver tries a few common table/column layouts used by bridgev2. If a query
// fails (unknown table/column), it is ignored. First successful hit wins.
//
// Returned thread IDs are normalized to strip "thread:" prefix if present.
//
// NOTE: This relies on the bridge having previously bridged a message for the given
// Message-ID. Fresh replies whose parent wasn't bridged won't resolve here and will
// fall back to the custom thread index and heuristics.

type DBThreadMetadataResolver struct {
	Bridge  *bridgev2.Bridge
	Log     *zerolog.Logger
	Network string // e.g. "email"
}

func (r *DBThreadMetadataResolver) ResolveThreadID(receiver, messageID string) (string, bool) {
	if r == nil || r.Bridge == nil || r.Bridge.DB == nil {
		return "", false
	}
	mid := strings.TrimSpace(messageID)
	if mid == "" {
		return "", false
	}
	ctx := context.Background()

	// Candidate queries. We try in order. Any SQL error is treated as a miss and we move on.
	// 1) Common layout: message(network, remote_id, receiver, portal_id)
	if tid := r.querySingleString(ctx, `SELECT portal_id FROM message WHERE network = ? AND remote_id = ? AND receiver = ?`, r.Network, mid, receiver); tid != "" {
		return normalizeThreadID(tid), true
	}
	// 2) Without receiver column
	if tid := r.querySingleString(ctx, `SELECT portal_id FROM message WHERE network = ? AND remote_id = ?`, r.Network, mid); tid != "" {
		return normalizeThreadID(tid), true
	}
	// 3) Alternate table name: messages
	if tid := r.querySingleString(ctx, `SELECT portal_id FROM messages WHERE network = ? AND remote_id = ? AND receiver = ?`, r.Network, mid, receiver); tid != "" {
		return normalizeThreadID(tid), true
	}
	if tid := r.querySingleString(ctx, `SELECT portal_id FROM messages WHERE network = ? AND remote_id = ?`, r.Network, mid); tid != "" {
		return normalizeThreadID(tid), true
	}

	if r.Log != nil {
		r.Log.Trace().Str("receiver", receiver).Str("message_id", mid).Msg("DB resolver: no mapping found for email Message-ID")
	}
	return "", false
}

func (r *DBThreadMetadataResolver) querySingleString(ctx context.Context, sql string, args ...any) string {
	rows, err := r.Bridge.DB.Query(ctx, sql, args...)
	if err != nil {
		return ""
	}
	defer rows.Close()
	if rows.Next() {
		var out string
		if err := rows.Scan(&out); err == nil {
			return out
		}
	}
	return ""
}

func normalizeThreadID(portalOrThreadID string) string {
	id := strings.TrimSpace(portalOrThreadID)
	if strings.HasPrefix(id, "thread:") {
		return strings.TrimPrefix(id, "thread:")
	}
	return id
}
