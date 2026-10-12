package testdata

import (
	"strings"
	"time"
)

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

// Wrapper is a generic type: skipped with a warning, it keeps using the Schema path.
type Wrapper[T any] struct {
	Value T `mask:"secret"`
}

// EmailMask is a custom type — its name contains "Mask", so codegen
// treats it as Maskable.
type EmailMask string

func (e EmailMask) Mask() (any, error) {
	s := string(e)
	if idx := strings.Index(s, "@"); idx > 0 {
		return EmailMask(s[:1] + "***" + s[idx:]), nil
	}
	return EmailMask("[EMAIL]"), nil
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

// UserID is a named string type; a tagged field of this type is redacted.
type UserID string

// Account has a tagged named-string field, a tagged *named-string, a
// time.Time and plain scalars: all handled or inert, so it is generated.
type Account struct {
	ID       UserID  `mask:"secret"`
	Backup   *UserID `mask:"secret"`
	Created  time.Time
	Attempts int
	Tags     []string
	Labels   map[string]string
	Done     func()
}

// Address has nothing to mask, so it is a safe nested value.
type Address struct {
	Street string
	Zip    string
}

// Customer nests an inert struct (value, pointer, slice, map) and is generated.
type Customer struct {
	Email   string `mask:"email"`
	Home    Address
	Work    *Address
	Past    []Address
	ByLabel map[string]Address
}

// Base is embedded; it has nothing to mask so the embedding type is generated.
type Base struct {
	ID int
}

// Employee embeds an inert struct.
type Employee struct {
	Base
	Phone string `mask:"phone"`
}

// ---- types below are skipped with a warning (see TestAnalyzeWarnings) ----

// HashTagged uses a transform other than redact.
type HashTagged struct {
	Token string `mask:"secret,hash"`
}

// PartialTagged uses a transform other than redact.
type PartialTagged struct {
	Phone string `mask:"phone,partial"`
}

// IntTagged tags a field the runtime would not mask either.
type IntTagged struct {
	PIN int `mask:"secret"`
}

// NestedTagged holds a struct that has tagged fields of its own.
type NestedTagged struct {
	Name    string
	Profile Account
}

// HasInterface holds a dynamic value.
type HasInterface struct {
	Email   string `mask:"email"`
	Payload any
}

// HasUnknownImport holds an imported type the generator cannot inspect.
type HasUnknownImport struct {
	Email string `mask:"email"`
	When  strings.Builder
}

// BadTag has a transform-only (v0.1) tag.
type BadTag struct {
	Token string `mask:"hash"`
}

// UnexportedTag tags a field that can never be masked.
type UnexportedTag struct {
	secret string `mask:"secret"`
}

// MaskableInMap holds Maskable values in a container.
type MaskableInMap struct {
	Email string `mask:"email"`
	ByKey map[string]EmailMask
}

// HandWritten declares its own Mask, so nothing is generated for it.
type HandWritten struct {
	Email string `mask:"email"`
}

func (h HandWritten) Mask() (any, error) { return HandWritten{Email: "[hand]"}, nil }
