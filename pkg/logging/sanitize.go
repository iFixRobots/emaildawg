package logging

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// Basic helpers usable across packages for sanitizing log values.

func MaskEmail(s string) string {
	s = strings.TrimSpace(s)
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return s
	}
	user := s[:at]
	domain := s[at+1:]
	mask := func(part string) string {
		if len(part) <= 1 {
			return "*"
		}
		return part[:1] + strings.Repeat("*", max(0, len(part)-2)) + part[len(part)-1:]
	}
	dParts := strings.Split(domain, ".")
	for i, p := range dParts {
		dParts[i] = mask(p)
	}
	return mask(user) + "@" + strings.Join(dParts, ".")
}

func HashHMAC(s, secret string, n int) string {
	// If secret is empty, avoid producing predictable hashes silently.
	// Fall back to hashing with a fixed label and input, which is still deterministic but
	// separates from the intended secret-based HMAC usage. Callers should set a secret.
	key := []byte(secret)
	if len(key) == 0 {
		key = []byte("emaildawg-hash")
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte(s))
	d := h.Sum(nil)
	hexStr := hex.EncodeToString(d)
	if n > 0 && n < len(hexStr) {
		return hexStr[:n]
	}
	return hexStr
}

func SummarizeIMAPData(data string) string {
	if len(data) == 0 {
		return ""
	}
	return "bytes=" + itoa(len(data))
}

// Minimal integer to string to avoid fmt in hot path.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

var emailRE = regexp.MustCompile(`(?i)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)

func RedactEmailsIn(s string) string {
	return emailRE.ReplaceAllStringFunc(s, MaskEmail)
}

// BoundAndClean trims control characters and bounds the length of arbitrary strings for safe logging.
func BoundAndClean(s string, max int) string {
	s = strings.TrimSpace(s)
	// Remove control characters
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 32 || r == 127 {
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if max > 0 && len(out) > max {
		return out[:max]
	}
	return out
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

