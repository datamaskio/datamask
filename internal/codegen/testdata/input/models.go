package testdata

import "strings"

// User has mask-tagged fields — should generate inline masking.
type User struct {
	Name  string
	Email string `mask:"email"`
	SSN   string `mask:"secret"`
}

// Config has a pointer-to-string mask-tagged field.
type Config struct {
	Name  string
	Token *string `mask:"secret"`
}

// NoTags has no mask tags and no Maskable fields — should NOT generate code.
type NoTags struct {
	Name  string
	Email string
}

// WithOmit has a mix of tagged and omitted fields.
type WithOmit struct {
	Name    string
	Public  string
	Secret  string `mask:"secret"`
	Private string `mask:"-"`
}

// Wrapper is a generic type with a mask-tagged field — delegates to datamask.Redact.
type Wrapper[T any] struct {
	Value T `mask:"secret"`
}

// EmailMask is a custom type — its name contains "Mask", so codegen
// treats it as Maskable.
type EmailMask string

func (e EmailMask) Mask() any {
	s := string(e)
	if idx := strings.Index(s, "@"); idx > 0 {
		return EmailMask(s[:1] + "***" + s[idx:])
	}
	return EmailMask("[EMAIL]")
}

// WithMaskable has a Maskable-typed field without a mask tag (tag-optional).
type WithMaskable struct {
	Name  string
	Email EmailMask
}

// WithMaskableTag has a Maskable-typed field with a mask tag (precedence).
type WithMaskableTag struct {
	Name  string
	Email EmailMask `mask:"email"`
}

// WithMaskablePointer has a *EmailMask field (pointer to Maskable).
type WithMaskablePointer struct {
	Name  string
	Email *EmailMask
}
