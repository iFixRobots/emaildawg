package connector

import (
	"context"
	"time"

	"maunium.net/go/mautrix/bridgev2/database"
)

// EmailAccount represents a stored email account with credentials
type EmailAccount struct {
	UserMXID     string    `json:"user_mxid"`
	Email        string    `json:"email"`
	Username     string    `json:"username"`
	Password     string    `json:"password"`
	Host         string    `json:"host"`
	Port         int       `json:"port"`
	TLS          bool      `json:"tls"`
	CreatedAt    time.Time `json:"created_at"`
	LastSyncTime time.Time `json:"last_sync_time"`
}

// EmailAccountQuery handles database operations for email accounts
type EmailAccountQuery struct {
	DB *database.Database
}

func (eaq *EmailAccountQuery) CreateTable(ctx context.Context) error {
	_, err := eaq.DB.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS email_accounts (
			user_mxid TEXT NOT NULL,
			email TEXT NOT NULL,
			username TEXT NOT NULL,
			password TEXT NOT NULL,
			host TEXT NOT NULL,
			port INTEGER NOT NULL,
			tls BOOLEAN NOT NULL,
			created_at TIMESTAMP NOT NULL,
			last_sync_time TIMESTAMP,
			PRIMARY KEY (user_mxid, email)
		)
	`)
	return err
}

func (eaq *EmailAccountQuery) GetAccount(ctx context.Context, userMXID, email string) (*EmailAccount, error) {
	account := &EmailAccount{}
	rows, err := eaq.DB.Query(ctx, `
		SELECT user_mxid, email, username, password, host, port, tls, created_at, last_sync_time
		FROM email_accounts
		WHERE user_mxid = ? AND email = ?
	`, userMXID, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	if !rows.Next() {
		return nil, nil // No account found
	}
	
	err = rows.Scan(
		&account.UserMXID, &account.Email, &account.Username, &account.Password,
		&account.Host, &account.Port, &account.TLS, &account.CreatedAt, &account.LastSyncTime,
	)
	return account, err
}

func (eaq *EmailAccountQuery) GetUserAccounts(ctx context.Context, userMXID string) ([]*EmailAccount, error) {
	rows, err := eaq.DB.Query(ctx, `
		SELECT user_mxid, email, username, password, host, port, tls, created_at, last_sync_time
		FROM email_accounts
		WHERE user_mxid = ?
		ORDER BY created_at ASC
	`, userMXID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var accounts []*EmailAccount
	for rows.Next() {
		account := &EmailAccount{}
		err = rows.Scan(
			&account.UserMXID, &account.Email, &account.Username, &account.Password,
			&account.Host, &account.Port, &account.TLS, &account.CreatedAt, &account.LastSyncTime,
		)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, rows.Err()
}

func (eaq *EmailAccountQuery) UpsertAccount(ctx context.Context, account *EmailAccount) error {
	_, err := eaq.DB.Exec(ctx, `
		INSERT OR REPLACE INTO email_accounts 
		(user_mxid, email, username, password, host, port, tls, created_at, last_sync_time)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, account.UserMXID, account.Email, account.Username, account.Password,
		account.Host, account.Port, account.TLS, account.CreatedAt, account.LastSyncTime)
	return err
}

func (eaq *EmailAccountQuery) DeleteAccount(ctx context.Context, userMXID, email string) error {
	_, err := eaq.DB.Exec(ctx, `
		DELETE FROM email_accounts
		WHERE user_mxid = ? AND email = ?
	`, userMXID, email)
	return err
}

func (eaq *EmailAccountQuery) UpdateLastSync(ctx context.Context, userMXID, email string, syncTime time.Time) error {
	_, err := eaq.DB.Exec(ctx, `
		UPDATE email_accounts
		SET last_sync_time = ?
		WHERE user_mxid = ? AND email = ?
	`, syncTime, userMXID, email)
	return err
}
