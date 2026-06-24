package datamask

import (
	"errors"
	"reflect"
	"testing"
)

// -- Test types --

type customer struct {
	Name  string
	Email string `mask:"email"`
	Phone string `mask:"phone"`
	SSN   string `mask:"secret"`
}

type untagged struct {
	Name  string
	Email string
}

type hasOmit struct {
	Public  string
	Private string `mask:"-"`
	Secret  string `mask:"secret"`
}

type withHash struct {
	Name  string
	Token string `mask:"hash"`
}

type withPartial struct {
	Name  string
	Phone string `mask:"partial"`
}

// -- Tests: New and Config --

func TestNewDefault(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
	if m.cfg.DetectSecrets != true {
		t.Error("DetectSecrets should default to true")
	}
	if m.cache == nil {
		t.Error("cache should be initialized")
	}
}

func TestNewWithOptions(t *testing.T) {
	m := New(
		WithSecretDetection(false),
		WithTokenizeKey("my-key"),
	)
	if m.cfg.DetectSecrets != false {
		t.Error("DetectSecrets should be false")
	}
	if m.cfg.TokenizeKey != "my-key" {
		t.Errorf("TokenizeKey = %q, want %q", m.cfg.TokenizeKey, "my-key")
	}
}

// -- Tests: Redact --

func TestRedact(t *testing.T) {
	m := New()
	user := customer{
		Name:  "John",
		Email: "john@example.com",
		Phone: "+1-555-1234",
		SSN:   "123-45-6789",
	}

	masked, err := Redact(m, user)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Original must not be mutated.
	if user.Email != "john@example.com" {
		t.Error("original Email was mutated")
	}
	if user.SSN != "123-45-6789" {
		t.Error("original SSN was mutated")
	}

	// Masked copy must have placeholders.
	if masked.Email != "[REDACTED]" {
		t.Errorf("Email = %q, want [REDACTED]", masked.Email)
	}
	if masked.Phone != "[REDACTED]" {
		t.Errorf("Phone = %q, want [REDACTED]", masked.Phone)
	}
	if masked.SSN != "[REDACTED]" {
		t.Errorf("SSN = %q, want [REDACTED]", masked.SSN)
	}
	if masked.Name != "John" {
		t.Errorf("Name = %q, want John (untagged field)", masked.Name)
	}
}

func TestRedactReturnsConcreteType(t *testing.T) {
	// Prove the generic Redact returns T, not any.
	// The caller can use the result without type assertion.
	m := New()
	user := customer{Name: "Jane", Email: "j@b.com", Phone: "555", SSN: "123"}

	masked, err := Redact(m, user)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Compile-time check: masked.Email is accessible without type assertion.
	_ = masked.Name
	_ = masked.Email
}

func TestRedactNoMaskableFields(t *testing.T) {
	m := New()
	u := untagged{Name: "John", Email: "john@example.com"}

	_, err := Redact(m, u)
	if !errors.Is(err, ErrNoMaskableFields) {
		t.Errorf("expected ErrNoMaskableFields, got %v", err)
	}
}

func TestRedactOmit(t *testing.T) {
	m := New()
	v := hasOmit{
		Public:  "public",
		Private: "private",
		Secret:  "secret-value",
	}

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if masked.Public != "public" {
		t.Errorf("Public = %q, want public (untagged)", masked.Public)
	}
	if masked.Private != "private" {
		t.Errorf("Private = %q, want private (mask:\"-\" excluded)", masked.Private)
	}
	if masked.Secret != "[REDACTED]" {
		t.Errorf("Secret = %q, want [REDACTED]", masked.Secret)
	}
}

func TestRedactHashStrategy(t *testing.T) {
	m := New()
	v := withHash{Name: "test", Token: "my-secret-token"}

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// HashStrategy should produce a sha256: prefix.
	if len(masked.Token) < 7 || masked.Token[:7] != "sha256:" {
		t.Errorf("Token = %q, expected sha256: prefix", masked.Token)
	}
	if masked.Token == "my-secret-token" {
		t.Error("Token was not hashed")
	}
}

func TestRedactPartialStrategy(t *testing.T) {
	m := New()
	v := withPartial{Name: "test", Phone: "123-45-6789"}

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if masked.Phone != "***-**-6789" {
		t.Errorf("Phone = %q, want ***-**-6789", masked.Phone)
	}
}

func TestRedactWithTokenizeKey(t *testing.T) {
	m := New(WithTokenizeKey("secret"))

	// Struct with a tokenize-tagged field.
	type tokStruct struct {
		ID string `mask:"tokenize"`
	}
	v := tokStruct{ID: "user-123"}

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if masked.ID == "user-123" {
		t.Error("ID was not tokenized")
	}
	if len(masked.ID) < 4 || masked.ID[:4] != "tok:" {
		t.Errorf("ID = %q, expected tok: prefix", masked.ID)
	}
}

func TestRedactNonStruct(t *testing.T) {
	m := New()
	_, err := Redact(m, 42)
	if err == nil {
		t.Error("expected error for non-struct type")
	}
}

// -- Tests: RedactInPlace --

func TestRedactInPlace(t *testing.T) {
	m := New()
	user := &customer{
		Name:  "John",
		Email: "john@example.com",
		SSN:   "123-45-6789",
	}

	err := m.RedactInPlace(user)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.Email != "[REDACTED]" {
		t.Errorf("Email = %q, want [REDACTED]", user.Email)
	}
	if user.SSN != "[REDACTED]" {
		t.Errorf("SSN = %q, want [REDACTED]", user.SSN)
	}
	if user.Name != "John" {
		t.Errorf("Name = %q, want John (untagged)", user.Name)
	}
}

func TestRedactInPlacePanicsOnNonPointer(t *testing.T) {
	m := New()
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for non-pointer")
		}
	}()

	m.RedactInPlace(customer{})
}

func TestRedactInPlacePanicsOnNil(t *testing.T) {
	m := New()
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil pointer")
		}
	}()

	var v *customer
	m.RedactInPlace(v)
}

// -- Tests: Apply --

func TestApply(t *testing.T) {
	m := New()
	user := customer{
		Name:  "John",
		Email: "john@example.com",
		Phone: "+1-555-1234",
		SSN:   "123-45-6789",
	}

	masked, err := Apply(m, user, m.RedactPII())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if masked.Email != "[REDACTED]" {
		t.Errorf("Email = %q, want [REDACTED]", masked.Email)
	}
	if masked.Name != "John" {
		t.Errorf("Name = %q, want John", masked.Name)
	}
}

func TestApplyReturnsConcreteType(t *testing.T) {
	m := New()
	v := customer{Name: "Jane"}

	result, _ := Apply(m, v, Identity())
	_ = result.Name // proves result is customer
}

func TestApplyError(t *testing.T) {
	m := New()
	fail := func(v any) (any, error) {
		return nil, errors.New("boom")
	}

	_, err := Apply(m, customer{}, Policy(fail))
	if err == nil {
		t.Error("expected error from policy")
	}
}

// -- Tests: Composed policies --

func TestRedactPIIPolicy(t *testing.T) {
	m := New()
	v := customer{
		Name:  "John",
		Email: "john@example.com",
		SSN:   "123-45-6789",
	}

	redacted, err := m.RedactPII()(v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := redacted.(customer)

	if r.Email != "[REDACTED]" {
		t.Errorf("Email = %q, want [REDACTED]", r.Email)
	}
}

func TestHashEmailsPolicy(t *testing.T) {
	m := New()
	v := withHash{Name: "test", Token: "my-token"}

	result, err := m.HashEmails()(v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := result.(withHash)

	if r.Token == "my-token" {
		t.Error("Token was not hashed")
	}
	if r.Name != "test" {
		t.Errorf("Name = %q, want test", r.Name)
	}
}

func TestComposedPolicy(t *testing.T) {
	m := New()
	v := customer{
		Name:  "John",
		Email: "john@example.com",
		SSN:   "123-45-6789",
	}

	p := Compose(m.RedactPII(), Identity())
	result, err := p(v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := result.(customer)

	if r.Email != "[REDACTED]" {
		t.Errorf("Email = %q, want [REDACTED]", r.Email)
	}
}

// -- Tests: type cache --

func TestMaskerReusesCache(t *testing.T) {
	m := New()

	_, _ = Redact(m, customer{Name: "A", Email: "a@b.com"})
	_, _ = Redact(m, customer{Name: "B", Email: "c@d.com"})

	// Cache should be populated after first call.
	meta, ok := m.cache.Load(reflect.TypeFor[customer]())
	if !ok {
		t.Error("cache miss after Redact — type should have been stored")
	}
	if len(meta.Fields) == 0 {
		t.Error("cached TypeMeta has no fields")
	}
}

func TestWithHashKeyOption(t *testing.T) {
	m := New(WithHashKey("salt"))
	if m.cfg.HashKey != "salt" {
		t.Errorf("HashKey = %q, want salt", m.cfg.HashKey)
	}
}

func TestRedactInPlaceUntagged(t *testing.T) {
	m := New()
	u := &untagged{Name: "John"}
	err := m.RedactInPlace(u)
	if !errors.Is(err, ErrNoMaskableFields) {
		t.Errorf("expected ErrNoMaskableFields, got %v", err)
	}
}

func TestRedactInPlacePanicsOnNonStructPointer(t *testing.T) {
	m := New()
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for pointer to non-struct")
		}
	}()
	x := 42
	_ = m.RedactInPlace(&x)
}

func TestRedactPIIOnNonStruct(t *testing.T) {
	m := New()
	result, err := m.RedactPII()(42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != 42 {
		t.Errorf("non-struct should pass through unchanged")
	}
}

func TestHashEmailsOnNonStruct(t *testing.T) {
	m := New()
	result, err := m.HashEmails()("hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "hello" {
		t.Errorf("non-struct should pass through unchanged")
	}
}

func TestRedactWithHashKey(t *testing.T) {
	// When HashKey is set, HashStrategy uses Tokenize (salted) instead of plain Hash.
	m := New(WithHashKey("salt"))
	type hashStruct struct {
		ID string `mask:"hash"`
	}
	v := hashStruct{ID: "my-token"}

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With HashKey set, transform routes to Tokenize (tok: prefix).
	if len(masked.ID) < 4 || masked.ID[:4] != "tok:" {
		t.Errorf("ID = %q, expected tok: prefix (HashKey routes to Tokenize)", masked.ID)
	}
}

func TestMaskerCacheDifferentTypes(t *testing.T) {
	m := New()

	_, _ = Redact(m, customer{Email: "a@b.com"})
	_, _ = Redact(m, untagged{})

	// Both types should be cached.
	if _, ok := m.cache.Load(reflect.TypeFor[customer]()); !ok {
		t.Error("customer type not cached")
	}
	if _, ok := m.cache.Load(reflect.TypeFor[untagged]()); !ok {
		t.Error("untagged type not cached")
	}
}
