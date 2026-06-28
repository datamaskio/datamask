package datamask

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"strings"
	"unicode/utf8"
)

// RedactValue returns the generic redaction placeholder.
func RedactValue(s string) string {
	return "[REDACTED]"
}

// RedactEmail returns the email redaction placeholder.
func RedactEmail(s string) string {
	return "[EMAIL]"
}

// RedactPhone returns the phone redaction placeholder.
func RedactPhone(s string) string {
	return "[PHONE]"
}

// RedactSecret returns the secret redaction placeholder.
func RedactSecret(s string) string {
	return "[REDACTED]"
}

// Hash returns the SHA-256 hash of s as a "sha256:<hex>" string.
// The hash is deterministic within a process lifetime.
func Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}

// Tokenize returns a stable HMAC-SHA256 pseudonym for s using key.
// Same (s, key) always produces the same output — useful for correlation
// across systems without exposing the original value.
// The output format is "tok:<hex>" to distinguish it from a raw hash.
//
// Prefer TokenizeWithMAC when calling repeatedly with the same key — it
// avoids allocating a new HMAC on every call.
func Tokenize(s string, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(s))
	return "tok:" + hex.EncodeToString(mac.Sum(nil))
}

// TokenizeWithMAC is like Tokenize but reuses a pre-computed HMAC
// instance. The mac is reset before use.
func TokenizeWithMAC(s string, mac hash.Hash) string {
	mac.Reset()
	mac.Write([]byte(s))
	return "tok:" + hex.EncodeToString(mac.Sum(nil))
}

// Partial masks s according to its apparent type. The format follows
// ADR-0016:
//
//   - Email:       j***@example.com    (first char + *** + domain)
//   - Phone-like:  ***-***-1234        (separators kept, last 3-4 visible)
//   - Generic:     abc***xyz           (first 3 + *** + last 3)
//   - Short (<6):  ***                 (fully masked)
func Partial(s string) string {
	if s == "" {
		return "***"
	}

	// Email: preserve first char of local part + domain.
	if strings.Contains(s, "@") {
		return partialEmail(s)
	}

	// Phone / SSN / credit-card pattern: digits with separators.
	// Preserve the last segment (3-4 chars), mask the rest while
	// keeping separator characters.
	if looksLikeStructured(s) {
		return partialStructured(s)
	}

	// Generic string.
	return partialGeneric(s)
}

// partialEmail masks the local part of an email address.
// "john@example.com" → "j***@example.com"
func partialEmail(s string) string {
	at := strings.Index(s, "@")
	if at <= 0 {
		return "***"
	}
	local := s[:at]
	domain := s[at:]
	first, _ := utf8.DecodeRuneInString(local)
	return string(first) + "***" + domain
}

// looksLikeStructured reports whether s contains mostly digits with
// separator characters (like phone numbers, SSNs, credit cards).
// A structured value must contain at least one separator to distinguish
// it from a plain digit string.
func looksLikeStructured(s string) bool {
	digits := 0
	separators := 0
	other := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		} else if r == '-' || r == ' ' || r == '.' || r == '(' || r == ')' || r == '+' {
			separators++
		} else {
			other++
		}
	}
	return digits >= 6 && separators > 0 && other == 0
}

// partialStructured masks all but the last segment of a structured value.
// "123-45-6789" → "***-**-6789"
// "+1-555-1234" → "***-***-1234"
func partialStructured(s string) string {
	// Walk backwards to find the last digit group boundary.
	end := len(s)
	for end > 0 && s[end-1] >= '0' && s[end-1] <= '9' {
		end--
	}
	// end is now at the start of the last digit group (or 0).
	start := end
	for start > 0 {
		if s[start-1] >= '0' && s[start-1] <= '9' {
			start--
		} else {
			break
		}
	}

	var b strings.Builder
	for i := 0; i < start; i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte('*')
		} else {
			b.WriteByte(s[i]) // preserve separator
		}
	}
	b.WriteString(s[start:])
	return b.String()
}

// partialGeneric masks a generic string: first 3 chars + *** + last 3 chars.
// If shorter than 6 runes, returns "***".
func partialGeneric(s string) string {
	// Fast path for ASCII — avoid []rune allocation.
	if len(s) >= 6 && isASCII(s) {
		return s[:3] + "***" + s[len(s)-3:]
	}
	runes := []rune(s)
	if len(runes) < 6 {
		return "***"
	}
	return string(runes[:3]) + "***" + string(runes[len(runes)-3:])
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
