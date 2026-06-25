package datamask

import (
	"strings"
	"testing"
)

func TestRedactValue(t *testing.T) {
	got := RedactValue("anything")
	if got != "[REDACTED]" {
		t.Errorf("RedactValue() = %q, want %q", got, "[REDACTED]")
	}
}

func TestRedactEmail(t *testing.T) {
	got := RedactEmail("john@example.com")
	if got != "[EMAIL]" {
		t.Errorf("RedactEmail() = %q, want %q", got, "[EMAIL]")
	}
}

func TestRedactPhone(t *testing.T) {
	got := RedactPhone("+1-555-1234")
	if got != "[PHONE]" {
		t.Errorf("RedactPhone() = %q, want %q", got, "[PHONE]")
	}
}

func TestRedactSecret(t *testing.T) {
	got := RedactSecret("123-45-6789")
	if got != "[REDACTED]" {
		t.Errorf("RedactSecret() = %q, want %q", got, "[REDACTED]")
	}
}

func TestHash(t *testing.T) {
	h1 := Hash("john@example.com")
	h2 := Hash("john@example.com")
	h3 := Hash("jane@example.com")

	if h1 != h2 {
		t.Errorf("Hash must be deterministic: %q != %q", h1, h2)
	}
	if h1 == h3 {
		t.Errorf("different inputs must produce different hashes")
	}
	if !strings.HasPrefix(h1, "sha256:") {
		t.Errorf("Hash must have sha256: prefix, got %q", h1)
	}
}

func TestHashEmpty(t *testing.T) {
	h := Hash("")
	if !strings.HasPrefix(h, "sha256:") {
		t.Errorf("Hash of empty string must have sha256: prefix")
	}
}

func TestTokenize(t *testing.T) {
	t1 := Tokenize("john@example.com", "secret-key")
	t2 := Tokenize("john@example.com", "secret-key")
	t3 := Tokenize("john@example.com", "different-key")
	t4 := Tokenize("jane@example.com", "secret-key")

	if t1 != t2 {
		t.Errorf("Tokenize must be deterministic per key: %q != %q", t1, t2)
	}
	if t1 == t3 {
		t.Errorf("different keys must produce different tokens")
	}
	if t1 == t4 {
		t.Errorf("different inputs must produce different tokens")
	}
	if !strings.HasPrefix(t1, "tok:") {
		t.Errorf("Tokenize must have tok: prefix, got %q", t1)
	}
}

func TestPartialEmpty(t *testing.T) {
	got := Partial("")
	if got != "***" {
		t.Errorf("Partial(\"\") = %q, want %q", got, "***")
	}
}

func TestPartialEmail(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"john@example.com", "j***@example.com"},
		{"a@b.com", "a***@b.com"},
		{"ab@c.com", "a***@c.com"},
		{"z@example.org", "z***@example.org"},
	}
	for _, tt := range tests {
		got := Partial(tt.in)
		if got != tt.want {
			t.Errorf("Partial(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestPartialPhoneSSN(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"123-45-6789", "***-**-6789"},
		{"4111-1111-1111-1111", "****-****-****-1111"},
		{"+1-555-123-4567", "+*-***-***-4567"},
	}
	for _, tt := range tests {
		got := Partial(tt.in)
		if got != tt.want {
			t.Errorf("Partial(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestPartialGeneric(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"sensitive_value", "sen***lue"},
		{"abcdefghij", "abc***hij"},
		{"1234567890", "123***890"},
	}
	for _, tt := range tests {
		got := Partial(tt.in)
		if got != tt.want {
			t.Errorf("Partial(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestPartialEmailNoAtSign(t *testing.T) {
	got := Partial("notanemail")
	if got != "not***ail" {
		t.Errorf("Partial(%q) = %q, want not***ail (generic masking)", "notanemail", got)
	}
}

func TestPartialEmailAtStart(t *testing.T) {
	got := Partial("@domain.com")
	if got != "***" {
		t.Errorf("Partial(%q) = %q, want ***", "@domain.com", got)
	}
}

func TestPartialStructuredAllDigits(t *testing.T) {
	// A pure digit string without separators → treated as generic.
	got := Partial("1234567890")
	if got != "123***890" {
		t.Errorf("Partial(%q) = %q, want 123***890", "1234567890", got)
	}
}

func TestPartialShort(t *testing.T) {
	tests := []string{"ab", "abc", "a", "abcde"}
	for _, s := range tests {
		got := Partial(s)
		if got != "***" {
			t.Errorf("Partial(%q) = %q, want %q (short string should be fully masked)", s, got, "***")
		}
	}
}

func TestPartialPreservesSeparators(t *testing.T) {
	got := Partial("123 456 7890")
	// Last digit group "7890" (4 chars), rest masked.
	want := "*** *** 7890"
	if got != want {
		t.Errorf("Partial(%q) = %q, want %q", "123 456 7890", got, want)
	}
}

// Fuzz tests

func FuzzRedactValue(f *testing.F) {
	f.Add("hello")
	f.Add("")
	f.Add("ghp_abc123def456ghi789jkl012mno345pqr")
	f.Fuzz(func(t *testing.T, s string) {
		// Redact must never panic and always return "[REDACTED]".
		got := RedactValue(s)
		if got != "[REDACTED]" {
			t.Errorf("RedactValue(%q) = %q, want [REDACTED]", s, got)
		}
	})
}

func FuzzHash(f *testing.F) {
	f.Add("hello")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		got := Hash(s)
		if !strings.HasPrefix(got, "sha256:") {
			t.Errorf("Hash must have sha256: prefix, got %q", got)
		}
	})
}

func FuzzPartial(f *testing.F) {
	f.Add("john@example.com")
	f.Add("123-45-6789")
	f.Add("hello world")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		// Partial must never panic.
		got := Partial(s)
		if got == "" {
			t.Errorf("Partial(%q) returned empty string", s)
		}
	})
}
