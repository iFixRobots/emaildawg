package connector

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
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

// --- Minimal AES-GCM helper and key management (self-contained) ---

const encPrefix = "v2:"

const (
	pbkdf2Iterations = 100000 // PBKDF2 iterations for key derivation
	saltSize        = 32      // Salt size in bytes
)

var (
	keyOnce sync.Once
	dbKey   []byte
	keyErr  error
)

func getDBKey() ([]byte, error) {
	keyOnce.Do(func() {
		// Use PBKDF2 with passphrase for better security
		passphrase := strings.TrimSpace(os.Getenv("EMAILDAWG_PASSPHRASE"))
		if passphrase == "" {
			keyErr = errors.New("EMAILDAWG_PASSPHRASE environment variable is required for secure credential storage")
			return
		}
		
		salt, err := getSalt()
		if err != nil {
			keyErr = fmt.Errorf("failed to get salt: %w", err)
			return
		}
		
		// Derive key using PBKDF2
		dbKey = pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iterations, 32, sha256.New)
	})
	if keyErr != nil {
		return nil, keyErr
	}
	if len(dbKey) != 32 {
		return nil, fmt.Errorf("derived key must be 32 bytes, got %d", len(dbKey))
	}
	return dbKey, nil
}

// getSalt returns the salt for PBKDF2, generating one if needed
func getSalt() ([]byte, error) {
	saltPath := filepath.Join(".", "data", "emaildawg.salt")
	
	// Try to read existing salt
	if data, err := os.ReadFile(saltPath); err == nil {
		salt, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err == nil && len(salt) == saltSize {
			return salt, nil
		}
	}
	
	// Generate new salt
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	
	// Create directory with secure permissions
	if err := os.MkdirAll(filepath.Join(".", "data"), 0o700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}
	
	// Save salt
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	if err := os.WriteFile(saltPath, []byte(saltB64), 0o600); err != nil {
		return nil, fmt.Errorf("failed to save salt: %w", err)
	}
	
	return salt, nil
}

func parseKeyString(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	// base64
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		if len(b) == 32 {
			return b, nil
		}
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		if len(b) == 32 {
			return b, nil
		}
	}
	// hex (allow 0x prefix)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if b, err := hex.DecodeString(s); err == nil {
		if len(b) == 32 {
			return b, nil
		}
	}
	return nil, errors.New("key must be 32 bytes in base64 or hex")
}

func encryptString(plain string) (string, error) {
	key, err := getDBKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, []byte(plain), nil)
	buf := append(nonce, ct...)
	return encPrefix + base64.StdEncoding.EncodeToString(buf), nil
}

func decryptString(stored string) (string, error) {
	// Check for old v1 encrypted data and provide helpful error message
	if strings.HasPrefix(stored, "v1:") {
		return "", errors.New("cannot decrypt old v1 encrypted data - please delete your database and reconfigure your email accounts with the new secure system using EMAILDAWG_PASSPHRASE environment variable")
	}
	
	// Only accept v2 encrypted data
	if !strings.HasPrefix(stored, encPrefix) {
		return "", errors.New("value is not encrypted with expected v2: prefix")
	}
	
	key, err := getDBKey()
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, encPrefix))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce := raw[:gcm.NonceSize()]
	ct := raw[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
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
	if err != nil {
		return nil, err
	}
	// Decrypt password (fresh deployments always store encrypted)
	plain, derr := decryptString(account.Password)
	if derr != nil {
		return nil, fmt.Errorf("failed to decrypt stored password: %w", derr)
	}
	account.Password = plain
	return account, nil
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
		plain, derr := decryptString(account.Password)
		if derr != nil {
			return nil, fmt.Errorf("failed to decrypt stored password: %w", derr)
		}
		account.Password = plain
		accounts = append(accounts, account)
	}
	return accounts, rows.Err()
}

func (eaq *EmailAccountQuery) UpsertAccount(ctx context.Context, account *EmailAccount) error {
	enc, err := encryptString(account.Password)
	if err != nil {
		return fmt.Errorf("failed to encrypt password: %w", err)
	}
	_, err = eaq.DB.Exec(ctx, `
		INSERT OR REPLACE INTO email_accounts 
		(user_mxid, email, username, password, host, port, tls, created_at, last_sync_time)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, account.UserMXID, account.Email, account.Username, enc,
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
