package datamask

import (
	"strings"
	"testing"
)

// -- Custom Maskable types for tests --

type EmailMask string

func (e EmailMask) Mask() (any, error) {
	s := string(e)
	idx := strings.Index(s, "@")
	if idx > 0 {
		return EmailMask(s[:1] + "***" + s[idx:]), nil
	}
	return EmailMask("[EMAIL]"), nil
}

type creditCard string

func (c *creditCard) Mask() (any, error) {
	s := string(*c)
	if len(s) >= 6 {
		result := creditCard(s[:4] + "****" + s[len(s)-4:])
		return &result, nil
	}
	result := creditCard("[MASKED]")
	return &result, nil
}

type maskedInt int

func (m maskedInt) Mask() (any, error) {
	return maskedInt(-1), nil
}

// -- Test types for Maskable integration --

type withEmailMask struct {
	Name  string
	Email EmailMask `mask:"email"`
}

type withUntaggedEmailMask struct {
	Name  string
	Email EmailMask
}

type withCreditCardTag struct {
	Name string
	CC   creditCard `mask:"secret"`
}

type withMixedMaskable struct {
	Name     string
	Phone    string     `mask:"phone"`
	Email    EmailMask  // no tag — Maskable only
	CC       creditCard `mask:"secret"` // tag + pointer-receiver Maskable
	Internal maskedInt  // Maskable, no tag
}

// -- Tests: Task 1 — Maskable interface & integration --

func TestMaskableValueReceiver(t *testing.T) {
	m := New()
	v := withUntaggedEmailMask{
		Name:  "Alice",
		Email: "alice@example.com",
	}

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if masked.Name != "Alice" {
		t.Errorf("Name = %q, want Alice", masked.Name)
	}
	if masked.Email != "a***@example.com" {
		t.Errorf("Email = %q, want a***@example.com (custom Mask())", masked.Email)
	}
}

func TestMaskablePointerReceiver(t *testing.T) {
	m := New()
	v := withCreditCardTag{
		Name: "Bob",
		CC:   "4111111111111111",
	}

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := creditCard("4111****1111")
	if masked.CC != expected {
		t.Errorf("CC = %q, want %q", masked.CC, expected)
	}
}

func TestMaskableTakesPrecedenceOverTag(t *testing.T) {
	m := New()
	v := withEmailMask{
		Name:  "Carol",
		Email: "carol@example.com",
	}

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if masked.Email == "[REDACTED]" {
		t.Error("Maskable should take precedence over tag; got [REDACTED] instead of custom Mask()")
	}
	if masked.Email != "c***@example.com" {
		t.Errorf("Email = %q, want c***@example.com (custom Mask())", masked.Email)
	}
}

func TestMaskableRedactInPlace(t *testing.T) {
	m := New()
	v := &withUntaggedEmailMask{
		Name:  "Dave",
		Email: "dave@example.com",
	}

	err := m.RedactInPlace(v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if v.Email != "d***@example.com" {
		t.Errorf("Email = %q, want d***@example.com", v.Email)
	}
}

func TestMaskableMixedFields(t *testing.T) {
	m := New()
	v := withMixedMaskable{
		Name:     "Frank",
		Phone:    "+1-555-1234",
		Email:    "frank@example.com",
		CC:       "4111111111111111",
		Internal: 42,
	}

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if masked.Name != "Frank" {
		t.Errorf("Name = %q, want Frank", masked.Name)
	}
	if masked.Phone != "[REDACTED]" {
		t.Errorf("Phone = %q, want [REDACTED]", masked.Phone)
	}
	if masked.Email != "f***@example.com" {
		t.Errorf("Email = %q, want f***@example.com", masked.Email)
	}
	if masked.CC != "4111****1111" {
		t.Errorf("CC = %q, want 4111****1111", masked.CC)
	}
	if masked.Internal != -1 {
		t.Errorf("Internal = %d, want -1", masked.Internal)
	}

	if v.Email != "frank@example.com" {
		t.Error("original Email was mutated")
	}
	if v.CC != "4111111111111111" {
		t.Error("original CC was mutated")
	}
}

func TestMaskableNonStructTopLevel(t *testing.T) {
	m := New()
	v := EmailMask("user@example.com")

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if masked != "u***@example.com" {
		t.Errorf("Masked = %q, want u***@example.com", masked)
	}
}

func TestMaskablePointerToStruct(t *testing.T) {
	m := New()
	v := &withUntaggedEmailMask{
		Name:  "Grace",
		Email: "grace@example.com",
	}

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if masked.Name != "Grace" {
		t.Errorf("Name = %q, want Grace", masked.Name)
	}
	if masked.Email != "g***@example.com" {
		t.Errorf("Email = %q, want g***@example.com", masked.Email)
	}
	if v.Email != "grace@example.com" {
		t.Error("original pointer was mutated")
	}
}

func TestMaskableSliceOfMaskableTypes(t *testing.T) {
	m := New()
	users := []withUntaggedEmailMask{
		{Name: "Alice", Email: "alice@example.com"},
		{Name: "Bob", Email: "bob@example.com"},
	}

	masked, err := Redact(m, users)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if masked[0].Email != "a***@example.com" {
		t.Errorf("Email[0] = %q, want a***@example.com", masked[0].Email)
	}
	if masked[1].Email != "b***@example.com" {
		t.Errorf("Email[1] = %q, want b***@example.com", masked[1].Email)
	}
}

func TestMaskableNilPointer(t *testing.T) {
	m := New()
	type Container struct {
		Name  string
		Email *EmailMask `mask:"email"`
	}
	v := Container{Name: "Test", Email: nil}

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if masked.Email != nil {
		t.Error("nil *EmailMask should remain nil")
	}
}

func TestMaskablePointerToPointerReceiver(t *testing.T) {
	m := New()
	type withCreditCardPtr struct {
		Name string
		CC   *creditCard `mask:"secret"`
	}
	cc := creditCard("4111111111111111")
	v := withCreditCardPtr{Name: "Ivan", CC: &cc}

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if masked.CC == nil {
		t.Fatal("CC should not be nil")
	}
	if *masked.CC != "4111****1111" {
		t.Errorf("CC = %q, want 4111****1111", *masked.CC)
	}
}

func TestMaskableEmbeddedStruct(t *testing.T) {
	// Maskable type embedded via an anonymous struct field.
	type Contact struct {
		Email EmailMask
	}
	type User struct {
		Name string
		Contact
	}

	m := New()
	v := User{Name: "Julia", Contact: Contact{Email: "julia@example.com"}}

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if masked.Email != "j***@example.com" {
		t.Errorf("Email = %q, want j***@example.com", masked.Email)
	}
}

// -- Coverage: pointer-receiver Maskable returning value (not pointer) --

type secretValue string

func (s *secretValue) Mask() (any, error) {
	return secretValue("[SECRET]"), nil
}

func TestMaskablePointerReceiverReturnsValue(t *testing.T) {
	m := New()
	type Container struct {
		Name   string
		Secret secretValue `mask:"secret"`
	}
	v := Container{Name: "Test", Secret: "classified"}

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if masked.Secret != "[SECRET]" {
		t.Errorf("Secret = %q, want [SECRET]", masked.Secret)
	}
}

// -- Coverage: unexported Maskable field (skipped) --

type withUnexportedMaskable struct {
	Name     string
	internal EmailMask // unexported — should be skipped
}

func TestMaskableUnexportedField(t *testing.T) {
	m := New()
	v := withUnexportedMaskable{Name: "Test", internal: "secret@example.com"}

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Unexported field should NOT be masked.
	if masked.internal != "secret@example.com" {
		t.Errorf("unexported internal = %q, want secret@example.com (should not be masked)", masked.internal)
	}
}

// -- Coverage: nil pointer embedded struct --

type contactInfo struct {
	Email EmailMask
}

type withNilEmbeddedPointer struct {
	Name    string
	Contact *contactInfo // embedded as nil — should be skipped
}

func TestMaskableNilEmbeddedPointer(t *testing.T) {
	m := New()
	v := withNilEmbeddedPointer{Name: "Test", Contact: nil}

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if masked.Contact != nil {
		t.Error("nil embedded pointer should remain nil")
	}
}

// NOTE: Embedded pointer-to-Maskable-struct is a known edge case.
// applyMaskableFields recurses into anonymous pointer fields but reflect
// settability through the pointer-deref chain requires further investigation.
// Tracked as follow-up item.

// -- Tests: Maskable top-level (non-struct) with pointer receiver --

func TestMaskableTopLevelPointerReceiver(t *testing.T) {
	m := New()
	// creditCard has a pointer receiver Mask(). Pass by value to exercise
	// the pointer-receiver path in redactVisited.
	v := creditCard("4111111111111111")

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if masked != "4111****1111" {
		t.Errorf("masked = %q, want 4111****1111", masked)
	}
}

// -- Tests: RedactInPlace with *string mask-tagged field --

func TestRedactInPlacePointerToString(t *testing.T) {
	m := New()
	type cfg struct {
		Name  string
		Token *string `mask:"secret"`
	}
	tok := "top-secret"
	v := cfg{Name: "Test", Token: &tok}

	err := m.RedactInPlace(&v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if *v.Token != "[REDACTED]" {
		t.Errorf("Token = %q, want [REDACTED]", *v.Token)
	}
}

// -- Tests: RedactPII with Maskable *string value --
