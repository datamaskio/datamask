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

	// TokenizeKey is the HMAC key used by the Tokenize transform.
	// Compile rejects schemas with tokenize fields when it is empty.
	TokenizeKey string

	// HashKey is the HMAC key used by the Hash transform. Compile rejects
	// schemas with hash fields when it is empty.
	HashKey string

	// MaxTraversalDepth is the maximum object graph depth during
	// Redact traversal. Default 100. Set to 0 to disable the limit
	// (not recommended). Exceeding the limit returns an error.
	MaxTraversalDepth int

	// tokenizeMAC is a pre-computed HMAC for the Tokenize strategy.
	// Built once at Masker construction to avoid per-call allocations.
	tokenizeMAC hash.Hash
}

// initTokenizeMAC pre-computes the HMAC for the Tokenize strategy so
// callers don't allocate on every Tokenize call..
func (c *Config) initTokenizeMAC() {
	if c.TokenizeKey != "" {
		c.tokenizeMAC = hmac.New(sha256.New, []byte(c.TokenizeKey))
	}
	if c.MaxTraversalDepth == 0 {
		c.MaxTraversalDepth = 100
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

// WithHashKey sets the HMAC key for the Hash transform.
func WithHashKey(key string) Option {
	return func(c *Config) {
		c.HashKey = key
	}
}

// WithMaxTraversalDepth sets the maximum object graph traversal depth
// during Redact. Default 100. Values <= 0 use the default.
func WithMaxTraversalDepth(depth int) Option {
	return func(c *Config) {
		c.MaxTraversalDepth = depth
	}
}
