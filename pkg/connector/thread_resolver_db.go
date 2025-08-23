package connector

import (
	"context"
	"strings"
	"time"

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
	// Use short timeout to avoid delaying email delivery - fast failure to heuristics is better UX
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Use single UNION query to check all possible table/column combinations efficiently
	// Try both raw and namespaced remote IDs to be robust
	candidates := []string{mid, "email:" + mid}
	
	// Build single query that tries all combinations with UNION
	unionQuery := `
		SELECT portal_id, 'message_with_receiver' as source FROM message 
		WHERE network = ? AND remote_id = ? AND receiver = ?
		UNION ALL
		SELECT portal_id, 'message_no_receiver' as source FROM message 
		WHERE network = ? AND remote_id = ?
		UNION ALL  
		SELECT portal_id, 'messages_with_receiver' as source FROM messages 
		WHERE network = ? AND remote_id = ? AND receiver = ?
		UNION ALL
		SELECT portal_id, 'messages_no_receiver' as source FROM messages 
		WHERE network = ? AND remote_id = ?
		LIMIT 1`
		
	for _, rid := range candidates {
		if result := r.queryUnionResult(ctx, unionQuery, r.Network, rid, receiver, r.Network, rid, r.Network, rid, receiver, r.Network, rid); result != "" {
			ntid := normalizeThreadID(result)
			if r.Log != nil {
				r.Log.Debug().Str("receiver", receiver).Str("remote_id", rid).Str("thread_id", ntid).Msg("DB resolver: resolved email message to thread")
			}
			return ntid, true
		}
	}

	if r.Log != nil {
		r.Log.Trace().Str("receiver", receiver).Str("message_id", mid).Msg("DB resolver: no mapping found for email Message-ID")
	}
	return "", false
}

func (r *DBThreadMetadataResolver) queryUnionResult(ctx context.Context, sql string, args ...any) string {
	start := time.Now()
	rows, err := r.Bridge.DB.Query(ctx, sql, args...)
	if err != nil {
		// Only log if it's not a simple "table doesn't exist" error (expected for best-effort)
		if r.Log != nil && !strings.Contains(strings.ToLower(err.Error()), "no such table") {
			r.Log.Debug().Err(err).Dur("duration", time.Since(start)).Msg("DB resolver union query failed")
		}
		return ""
	}
	defer rows.Close()
	
	if rows.Next() {
		var portalID, source string
		if err := rows.Scan(&portalID, &source); err == nil {
			if r.Log != nil {
				duration := time.Since(start)
				if duration > 500*time.Millisecond {
					r.Log.Warn().Dur("duration", duration).Str("source", source).Msg("DB resolver union query was slow")
				}
			}
			return portalID
		}
		if r.Log != nil {
			r.Log.Debug().Err(err).Msg("DB resolver union scan failed")
		}
	}
	return ""
}

func (r *DBThreadMetadataResolver) querySingleString(ctx context.Context, sql string, args ...any) string {
	start := time.Now()
	rows, err := r.Bridge.DB.Query(ctx, sql, args...)
	if err != nil {
		// Only log if it's not a simple "table doesn't exist" error (expected for best-effort)
		if r.Log != nil && !strings.Contains(strings.ToLower(err.Error()), "no such table") {
			r.Log.Debug().Err(err).Dur("duration", time.Since(start)).Msg("DB resolver query failed")
		}
		return ""
	}
	defer rows.Close()
	
	if rows.Next() {
		var out string
		if err := rows.Scan(&out); err == nil {
			if r.Log != nil {
				duration := time.Since(start)
				if duration > 500*time.Millisecond {
					r.Log.Warn().Dur("duration", duration).Msg("DB resolver query was slow")
				}
			}
			return out
		}
		if r.Log != nil {
			r.Log.Debug().Err(err).Msg("DB resolver scan failed")
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
