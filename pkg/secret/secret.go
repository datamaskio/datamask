// Package secret detects known secret formats (API keys, tokens, PANs,
// JWTs) in strings and struct values.
package secret

import (
	"reflect"
	"strings"

	"github.com/datamaskio/datamask/internal/patterns"
)

// Finding describes a detected secret.
type Finding struct {
	// Type is the pattern name, e.g. "GitHubPAT", "AWSKey", "JWT".
	Type string

	// Field is the struct field name, or empty for Detect (plain string).
	Field string

	// Position is the byte offset where the secret was found.
	Position int

	// Value is the first 4 characters of the secret followed by "...".
	Value string
}

// Detect scans s against all known secret patterns and returns findings.
// Returns nil if no secrets are detected.
func Detect(s string) []Finding {
	return detectString(s, "")
}

// DetectAll walks the exported string fields of v and scans each for
// secrets. v must be a struct or a pointer to a struct. Each Finding
// includes the field name. Non-string fields and unexported fields are
// skipped.
func DetectAll(v any) []Finding {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil
	}

	var findings []Finding
	walkStruct(rv, "", &findings)
	return findings
}

// detectString scans s against all patterns and returns findings.
func detectString(s string, fieldName string) []Finding {
	if s == "" {
		return nil
	}
	// Fast pre-filter: all 8 patterns require ≥13 characters (PAN).
	// Most log values (names, statuses, IDs, short tokens) are much
	// shorter — skip them without running any regex.
	if len(s) < 13 {
		return nil
	}
	// Substring check: if the string doesn't contain any known secret
	// prefix (or a credit-card-like digit sequence), skip regexes.
	// This is O(len(s)) per string but ~100x cheaper than 8 FindIndex calls.
	if !mayContainSecret(s) {
		return nil
	}

	var findings []Finding
	for _, p := range patterns.All {
		locs := p.FindIndex(s)
		for _, loc := range locs {
			match := s[loc[0]:loc[1]]
			findings = append(findings, Finding{
				Type:     p.Name,
				Field:    fieldName,
				Position: loc[0],
				Value:    truncate(match),
			})
		}
	}
	return findings
}

// mayContainSecret reports whether s contains a substring that looks
// like the start of a known secret format. This is intentionally cheap
// — false positives are fine (we fall through to regex), but false
// negatives would skip regex and miss a real secret.
func mayContainSecret(s string) bool {
	// Check for known secret prefixes — derived from the pattern library.
	// False positives are harmless: regex rejects them downstream.
	for _, prefix := range patterns.Prefixes() {
		if strings.Contains(s, prefix) {
			return true
		}
	}
	// PAN has no fixed prefix — check for 13+ consecutive digits.
	return likelyPAN(s)
}

// likelyPAN reports whether s might contain a credit card number.
func likelyPAN(s string) bool {
	digits := 0
	for i := range len(s) {
		if s[i] >= '0' && s[i] <= '9' {
			digits++
			if digits >= 13 {
				return true
			}
		} else if s[i] != '-' && s[i] != ' ' {
			digits = 0 // non-separator, non-digit → reset
		}
	}
	return false
}

// truncate returns the first 4 characters of s followed by "...".
func truncate(s string) string {
	if len(s) <= 4 {
		return s
	}
	return s[:4] + "..."
}

// walkStruct recursively walks the struct value v, calling detectString
// on every exported string field. fieldNamePrefix is prepended to the
// field name for nested structs (e.g. "Address.Zip").
func walkStruct(v reflect.Value, fieldNamePrefix string, findings *[]Finding) {
	t := v.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue // unexported
		}

		fv := v.Field(i)
		name := f.Name
		if fieldNamePrefix != "" {
			name = fieldNamePrefix + "." + f.Name
		}

		if f.Anonymous {
			// Embedded struct — promote its fields.
			if fv.Kind() == reflect.Pointer {
				if fv.IsNil() {
					continue
				}
				fv = fv.Elem()
			}
			if fv.Kind() == reflect.Struct {
				walkStruct(fv, fieldNamePrefix, findings)
			}
			continue
		}

		// Dereference pointer fields.
		if fv.Kind() == reflect.Pointer {
			if fv.IsNil() {
				continue
			}
			fv = fv.Elem()
		}

		switch fv.Kind() {
		case reflect.String:
			f := detectString(fv.String(), name)
			*findings = append(*findings, f...)
		case reflect.Struct:
			// Recurse into nested (non-anonymous) struct fields.
			walkStruct(fv, name, findings)
		}
	}
}
