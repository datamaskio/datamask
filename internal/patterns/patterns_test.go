package patterns

import (
	"strings"
	"testing"
)

func TestAWSKeyMatch(t *testing.T) {
	examples := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"AKIA1234567890ABCDEF",
		"ASIA1234567890ABCDEF",
	}

	nonMatches := []string{
		"hello world",
		"AKIA123",                            // too short
		"AKIA1234567890ABCDEFG",              // too long (17 after AKIA)
		"user@example.com",                   // email
		"ghp_1234567890abcdef1234567890abcd", // GitHub token
	}

	for _, ex := range examples {
		if !AWSKey.Match(ex) {
			t.Errorf("AWSKey.Match(%q) = false, want true", ex)
		}
	}
	for _, nm := range nonMatches {
		if AWSKey.Match(nm) {
			t.Errorf("AWSKey.Match(%q) = true, want false", nm)
		}
	}
}

func TestGitHubPATMatch(t *testing.T) {
	examples := []string{
		"ghp_1234567890abcdefghijklmnopqrstuvwxyz",
		"ghp_" + strings.Repeat("a", 36),
	}

	nonMatches := []string{
		"hello world",
		"ghp_abc",                         // too short
		"github_pat_1234567890abcdefghij", // fine-grained format
		"AKIAIOSFODNN7EXAMPLE",            // AWS key
	}

	for _, ex := range examples {
		if !GitHubPAT.Match(ex) {
			t.Errorf("GitHubPAT.Match(%q) = false, want true", ex)
		}
	}
	for _, nm := range nonMatches {
		if GitHubPAT.Match(nm) {
			t.Errorf("GitHubPAT.Match(%q) = true, want false", nm)
		}
	}
}

func TestGitHubFineGrainedMatch(t *testing.T) {
	examples := []string{
		"github_pat_1234567890abcdefghijklmnopqrstuvwxyz",
		"github_pat_" + strings.Repeat("a", 36),
	}

	nonMatches := []string{
		"ghp_1234567890abcdefghijklmnopqrstuvwxyz", // classic format
	}

	for _, ex := range examples {
		if !GitHubFineGrained.Match(ex) {
			t.Errorf("GitHubFineGrained.Match(%q) = false, want true", ex)
		}
	}
	for _, nm := range nonMatches {
		if GitHubFineGrained.Match(nm) {
			t.Errorf("GitHubFineGrained.Match(%q) = true, want false", nm)
		}
	}
}

func TestOpenAIKeyMatch(t *testing.T) {
	examples := []string{
		"sk-" + strings.Repeat("a", 48),
		"sk-proj-" + strings.Repeat("b", 48),
	}

	nonMatches := []string{
		"hello world",
		"sk-short", // too short
		"sk_live_1234567890abcdefghij", // Stripe key
	}

	for _, ex := range examples {
		if !OpenAIKey.Match(ex) {
			t.Errorf("OpenAIKey.Match(%q) = false, want true", ex)
		}
	}
	for _, nm := range nonMatches {
		if OpenAIKey.Match(nm) {
			t.Errorf("OpenAIKey.Match(%q) = true, want false", nm)
		}
	}
}

func TestStripeLiveKeyMatch(t *testing.T) {
	examples := []string{
		"sk_live_" + strings.Repeat("a", 24),
		"sk_live_1234567890abcdefghijklmn",
	}

	nonMatches := []string{
		"hello world",
		"sk_test_1234567890abcdefghijklmn", // test key
		"sk-" + strings.Repeat("a", 48),    // OpenAI key
	}

	for _, ex := range examples {
		if !StripeLiveKey.Match(ex) {
			t.Errorf("StripeLiveKey.Match(%q) = false, want true", ex)
		}
	}
	for _, nm := range nonMatches {
		if StripeLiveKey.Match(nm) {
			t.Errorf("StripeLiveKey.Match(%q) = true, want false", nm)
		}
	}
}

func TestStripeTestKeyMatch(t *testing.T) {
	examples := []string{
		"sk_test_" + strings.Repeat("a", 24),
	}

	for _, ex := range examples {
		if !StripeTestKey.Match(ex) {
			t.Errorf("StripeTestKey.Match(%q) = false, want true", ex)
		}
	}
}

func TestPANMatch(t *testing.T) {
	examples := []string{
		"4111111111111111",       // Visa 16-digit
		"5500000000000004",       // Mastercard
		"340000000000009",        // Amex 15-digit
		"6011000000000004",       // Discover
		"4111-1111-1111-1111",    // Visa with dashes
		"5500 0000 0000 0004",    // Mastercard with spaces
		"3400-000000-00009",      // Amex with dash
		"4111 1111 1111 1111",    // Visa with spaces
	}

	nonMatches := []string{
		"hello world",
		"1234567890123456",       // random 16 digits (doesn't match IIN)
		"1234-5678-9012-3456",    // random with dashes
		"9999999999999999",       // invalid IIN
	}

	for _, ex := range examples {
		if !PAN.Match(ex) {
			t.Errorf("PAN.Match(%q) = false, want true", ex)
		}
	}
	for _, nm := range nonMatches {
		if PAN.Match(nm) {
			t.Errorf("PAN.Match(%q) = true, want false", nm)
		}
	}
}

func TestJWTMatch(t *testing.T) {
	// Real-looking JWT (not actually signed).
	examples := []string{
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlGMvF0K0mR0",
		"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	}

	nonMatches := []string{
		"hello world",
		"eyJ.not-a-token.missing",
		"abc.def.ghi", // doesn't start with eyJ
	}

	for _, ex := range examples {
		if !JWT.Match(ex) {
			t.Errorf("JWT.Match(%q) = false, want true", ex)
		}
	}
	for _, nm := range nonMatches {
		if JWT.Match(nm) {
			t.Errorf("JWT.Match(%q) = true, want false", nm)
		}
	}
}

func TestFindReturnsAllMatches(t *testing.T) {
	// Text with multiple secrets embedded.
	text := "key1: AKIAIOSFODNN7EXAMPLE and key2: ghp_1234567890abcdefghijklmnopqrstuvwxyz"

	awsMatches := AWSKey.Find(text)
	if len(awsMatches) != 1 {
		t.Errorf("AWSKey.Find: expected 1 match, got %d: %v", len(awsMatches), awsMatches)
	}

	ghMatches := GitHubPAT.Find(text)
	if len(ghMatches) != 1 {
		t.Errorf("GitHubPAT.Find: expected 1 match, got %d: %v", len(ghMatches), ghMatches)
	}
}

func TestFindNoMatch(t *testing.T) {
	text := "hello world, nothing to see here"

	for _, p := range All {
		matches := p.Find(text)
		if len(matches) != 0 {
			t.Errorf("%s.Find: expected 0 matches, got %v", p.Name, matches)
		}
	}
}

func TestAllSlice(t *testing.T) {
	if len(All) != 8 {
		t.Errorf("expected 8 patterns in All, got %d", len(All))
	}
	names := make(map[string]bool)
	for _, p := range All {
		if p.Name == "" {
			t.Error("pattern has empty name")
		}
		if names[p.Name] {
			t.Errorf("duplicate pattern name: %s", p.Name)
		}
		names[p.Name] = true
	}
}

func FuzzPatterns(f *testing.F) {
	f.Add("hello world")
	f.Add("AKIAIOSFODNN7EXAMPLE")
	f.Add("ghp_1234567890abcdefghijklmnopqrstuvwxyz")
	f.Add("sk-" + strings.Repeat("a", 48))
	f.Add("")

	f.Fuzz(func(t *testing.T, s string) {
		// Find must never panic.
		for _, p := range All {
			_ = p.Find(s)
			_ = p.Match(s)
		}
	})
}
