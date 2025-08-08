package connector

import (
	"context"
	"maunium.net/go/mautrix/bridgev2/database"
)

// EmailThreadIndexQuery stores a mapping from (receiver, message_id) -> thread_id
// to allow reply threading across restarts.
type EmailThreadIndexQuery struct {
	DB *database.Database
}

func (q *EmailThreadIndexQuery) CreateTable(ctx context.Context) error {
	_, err := q.DB.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS email_thread_index (
			receiver TEXT NOT NULL,
			message_id TEXT NOT NULL,
			thread_id TEXT NOT NULL,
			PRIMARY KEY (receiver, message_id)
		)
	`)
	return err
}

// Internal context-aware getter.
func (q *EmailThreadIndexQuery) GetThreadIDForCtx(ctx context.Context, receiver, messageID string) (string, error) {
	rows, err := q.DB.Query(ctx, `
		SELECT thread_id FROM email_thread_index WHERE receiver = ? AND message_id = ?
	`, receiver, messageID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if rows.Next() {
		var tid string
		if err := rows.Scan(&tid); err != nil {
			return "", err
		}
		return tid, nil
	}
	return "", nil
}

// Internal context-aware mapper.
func (q *EmailThreadIndexQuery) MapThreadIDsCtx(ctx context.Context, receiver, threadID string, messageIDs []string) error {
	if len(messageIDs) == 0 {
		return nil
	}
	for _, mid := range messageIDs {
		if mid == "" {
			continue
		}
		_, err := q.DB.Exec(ctx, `
			INSERT OR REPLACE INTO email_thread_index (receiver, message_id, thread_id)
			VALUES (?, ?, ?)
		`, receiver, mid, threadID)
		if err != nil {
			return err
		}
	}
	return nil
}

// Implement email.ThreadIndex interface (no context) by delegating to *Ctx variants.
func (q *EmailThreadIndexQuery) GetThreadIDFor(receiver, messageID string) (string, error) {
	return q.GetThreadIDForCtx(context.Background(), receiver, messageID)
}

func (q *EmailThreadIndexQuery) MapThreadIDs(receiver, threadID string, messageIDs []string) error {
	return q.MapThreadIDsCtx(context.Background(), receiver, threadID, messageIDs)
}

