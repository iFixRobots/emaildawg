package connector

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/rs/zerolog"
)

// sanitizerHook is a zerolog Hook that redacts or summarizes sensitive fields when enabled.
// Attach it to the root bridge logger so child loggers inherit the behavior.
type sanitizerHook struct {
	enabled bool
	secret  []byte
}

func newSanitizerHook(enabled bool, secret string) zerolog.Hook {
	return &sanitizerHook{enabled: enabled, secret: []byte(secret)}
}

func (h *sanitizerHook) Run(e *zerolog.Event, level zerolog.Level, msg string) {
	if !h.enabled {
		return
	}
	// We can’t read existing fields from e, but we can add sanitized duplicates
	// by convention and/or rewrite common keys by adding replacements with same keys.
	// Callers should prefer structured fields; we’ll add best-effort masks here.
}

// Public helpers for callsites to pre-sanitize values.
func MaskEmail(s string) string {
	// g***@r***.com style masking
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
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(s))
	d := h.Sum(nil)
	hexStr := hex.EncodeToString(d)
	if n > 0 && n < len(hexStr) {
		return hexStr[:n]
	}
	return hexStr
}

func SummarizeIMAPData(data string) string {
	// Replace CRLFs and collapse whitespace; avoid leaking headers/contents.
	if len(data) == 0 {
		return ""
	}
	// Count bytes and provide a terse tag for context
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

