package datamask

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

// Config holds the configuration for a Masker.
// The zero value is usable: secret detection is off, and Tokenize/Hash
// produce deterministic but not cryptographically isolated output.
type Config struct {
	// DetectSecrets enables automatic secret pattern detection.
	// When true, the Masker scans string values for known secret
	// formats (API keys, tokens, JWTs) during Redact.
	DetectSecrets bool

	// TokenizeKey is the HMAC key used by the Tokenize strategy.
	// A zero-value key still produces pseudonyms but with no
	// cryptographic isolation from other deployments.
	TokenizeKey string

	// HashKey is reserved for future use (salted hashing).
	HashKey string

	// tokenizeMAC is a pre-computed HMAC for the Tokenize strategy.
	// Built once at Masker construction to avoid per-call allocations.
	tokenizeMAC hash.Hash
}

// initTokenizeMAC pre-computes the HMAC for the Tokenize strategy so
// callers don't allocate on every Tokenize call.
func (c *Config) initTokenizeMAC() {
	if c.TokenizeKey != "" {
		c.tokenizeMAC = hmac.New(sha256.New, []byte(c.TokenizeKey))
	}
}

// Option is a functional option for configuring a Masker.
type Option func(*Config)

// WithSecretDetection enables or disables automatic secret detection.
func WithSecretDetection(enabled bool) Option {
	return func(c *Config) {
		c.DetectSecrets = enabled
	}
}

// WithTokenizeKey sets the HMAC key for the Tokenize strategy.
func WithTokenizeKey(key string) Option {
	return func(c *Config) {
		c.TokenizeKey = key
	}
}

// WithHashKey sets the hash key for future salted-hashing support.
func WithHashKey(key string) Option {
	return func(c *Config) {
		c.HashKey = key
	}
}
