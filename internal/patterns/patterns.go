// Package patterns provides pre-compiled regular expressions for
// detecting high-confidence secret formats (API keys, tokens, JWTs).
// Every pattern is compiled once at init time and is safe for
// concurrent use.
package patterns

import "regexp"

// Pattern is a compiled regex for detecting a specific secret format.
type Pattern struct {
	Name   string
	Prefix string // substring always present in matches ("" for PAN — checked separately)
	re     *regexp.Regexp
}

// Find returns all non-overlapping matches of the pattern in s.
func (p *Pattern) Find(s string) []string {
	return p.re.FindAllString(s, -1)
}

// FindIndex returns the byte-index pairs of all matches of the pattern in s.
// Each pair is [start, end). Use this when you need match positions.
func (p *Pattern) FindIndex(s string) [][]int {
	return p.re.FindAllStringIndex(s, -1)
}

// Match reports whether the pattern matches the string s in its entirety.
// This is stricter than Find — it checks that the whole string is a secret.
func (p *Pattern) Match(s string) bool {
	return p.re.MatchString(s) && len(p.re.FindString(s)) == len(s) && len(s) > 0
}

// Pre-compiled patterns for high-confidence secret formats.
var (
	// AWSKey matches AWS access key IDs.
	// Format: AKIA or ASIA followed by 16 uppercase alphanumeric chars.
	AWSKey = &Pattern{
		Name:   "AWSKey",
		Prefix: "AKIA",
		re:     regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`),
	}

	// GitHubPAT matches GitHub personal access tokens (classic format).
	// Format: ghp_ followed by 36+ alphanumeric chars.
	GitHubPAT = &Pattern{
		Name:   "GitHubPAT",
		Prefix: "ghp_",
		re:     regexp.MustCompile(`ghp_[A-Za-z0-9]{36,}`),
	}

	// GitHubFineGrained matches GitHub fine-grained PATs.
	// Format: github_pat_ followed by 36+ alphanumeric/underscore chars.
	GitHubFineGrained = &Pattern{
		Name:   "GitHubFineGrained",
		Prefix: "github_pat_",
		re:     regexp.MustCompile(`github_pat_[A-Za-z0-9_]{36,}`),
	}

	// OpenAIKey matches OpenAI API keys and project keys.
	// Format: sk- or sk-proj- followed by 48+ alphanumeric/dash chars.
	OpenAIKey = &Pattern{
		Name:   "OpenAIKey",
		Prefix: "sk-",
		re:     regexp.MustCompile(`sk-(?:proj-)?[A-Za-z0-9\-]{48,}`),
	}

	// StripeLiveKey matches Stripe live secret keys.
	// Format: sk_live_ followed by 24+ alphanumeric chars.
	StripeLiveKey = &Pattern{
		Name:   "StripeLiveKey",
		Prefix: "sk-",
		re:     regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`),
	}

	// StripeTestKey matches Stripe test secret keys.
	// Format: sk_test_ followed by 24+ alphanumeric chars.
	StripeTestKey = &Pattern{
		Name:   "StripeTestKey",
		Prefix: "sk-",
		re:     regexp.MustCompile(`sk_test_[A-Za-z0-9]{24,}`),
	}

	// PAN matches credit/debit card primary account numbers.
	// Matches common issuer formats (Visa, Mastercard, Amex, Discover)
	// with optional dashes or spaces as digit-group separators.
	// The pattern detects 13–19 digit PANs but does not validate the
	// Luhn checksum — callers should verify checksums separately for
	// high-confidence detection.
	PAN = &Pattern{
		Name:   "PAN",
		Prefix: "", // no fixed prefix — checked via likelyPAN
		re:     regexp.MustCompile(`\b(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}|6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4})\b`),
	}

	// JWT matches JSON Web Tokens.
	// Format: three base64url-encoded segments separated by dots.
	// The header segment always starts with "eyJ" (encoded "{").
	JWT = &Pattern{
		Name:   "JWT",
		Prefix: "eyJ",
		re:     regexp.MustCompile(`eyJ[A-Za-z0-9\-_]+\.([A-Za-z0-9\-_]+)\.([A-Za-z0-9\-_]+)`),
	}
)

// Prefixes returns the unique, non-empty prefix substrings across all
// patterns. Useful for fast pre-filtering before regex scanning.
func Prefixes() []string {
	seen := make(map[string]bool)
	var prefixes []string
	for _, p := range All {
		if p.Prefix != "" && !seen[p.Prefix] {
			seen[p.Prefix] = true
			prefixes = append(prefixes, p.Prefix)
		}
	}
	return prefixes
}

// All is a slice of all pre-compiled patterns. Useful for scanning
// a value against every known format.
var All = []*Pattern{
	AWSKey,
	GitHubPAT,
	GitHubFineGrained,
	OpenAIKey,
	StripeLiveKey,
	StripeTestKey,
	PAN,
	JWT,
}
