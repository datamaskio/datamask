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
	Token string `mask:"secret,hash"`
}

type withPartial struct {
	Name  string
	Phone string `mask:"phone,partial"`
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

	masked, err := Redact(m, u)
	if err != nil {
		t.Errorf("unexpected error for untagged struct: %v", err)
	}
	// Value should be returned unchanged, no error.
	if masked.Name != "John" {
		t.Errorf("Name = %q, want John (unchanged)", masked.Name)
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
		ID string `mask:"secret,tokenize"`
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

func TestRedactInPlaceErrorOnNonPointer(t *testing.T) {
	m := New()
	err := m.RedactInPlace(customer{})
	if err == nil {
		t.Error("expected error for non-pointer")
	}
}

func TestRedactInPlaceErrorOnNil(t *testing.T) {
	m := New()
	var v *customer
	err := m.RedactInPlace(v)
	if err == nil {
		t.Error("expected error for nil pointer")
	}
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

func TestRedactPointerToStringField(t *testing.T) {
	m := New()
	type apiConfig struct {
		Token *string `mask:"secret"`
	}
	tok := "my-secret-token"
	v := apiConfig{Token: &tok}

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *masked.Token != "[REDACTED]" {
		t.Errorf("Token = %q, want [REDACTED]", *masked.Token)
	}
	if *v.Token != "my-secret-token" {
		t.Error("original *string was mutated")
	}
}

func TestRedactNilPointerToString(t *testing.T) {
	m := New()
	type apiConfig struct {
		Token *string `mask:"secret"`
	}
	v := apiConfig{Token: nil}

	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if masked.Token != nil {
		t.Error("nil *string should remain nil")
	}
}

func TestRedactCyclicStruct(t *testing.T) {
	m := New()
	type Node struct {
		Name string `mask:"secret"`
		Next *Node
	}
	node := &Node{Name: "first"}
	node.Next = node // self-referential

	// Should not stack-overflow.
	_, err := Redact(m, node)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRedactPIIWithPointerToString(t *testing.T) {
	m := New()
	type cfg struct {
		Name  string
		Token *string `mask:"secret"`
	}
	tok := "sauce"
	v := cfg{Name: "test", Token: &tok}

	result, _ := m.RedactPII()(v)
	r := result.(cfg)
	if *r.Token != "[REDACTED]" {
		t.Errorf("Token = %q, want [REDACTED]", *r.Token)
	}
}

func TestHashEmailsWithPointerToString(t *testing.T) {
	m := New()
	type cfg struct {
		Name  string
		Token *string `mask:"secret,hash"`
	}
	tok := "secret"
	v := cfg{Name: "test", Token: &tok}

	result, _ := m.HashEmails()(v)
	r := result.(cfg)
	if *r.Token == tok {
		t.Error("Token should be hashed, not same as original")
	}
}

func TestRedactTokenizeWithMAC(t *testing.T) {
	m := New(WithTokenizeKey("my-key"))
	type rec struct {
		ID string `mask:"secret,tokenize"`
	}
	v := rec{ID: "user-1"}
	masked, err := Redact(m, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if masked.ID == "user-1" {
		t.Error("ID should be tokenized")
	}
}

func TestRedactAny(t *testing.T) {
	m := New()
	user := customer{Email: "a@b.com", SSN: "123-45-6789"}

	result, err := m.RedactAny(user)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	masked := result.(customer)
	if masked.Email != "[REDACTED]" {
		t.Errorf("Email = %q, want [REDACTED]", masked.Email)
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
	if err != nil {
		t.Errorf("unexpected error for untagged struct: %v", err)
	}
	// Value should be unchanged, no error.
	if u.Name != "John" {
		t.Errorf("Name = %q, want John", u.Name)
	}
}

func TestRedactInPlaceErrorOnNonStructPointer(t *testing.T) {
	m := New()
	x := 42
	err := m.RedactInPlace(&x)
	if err == nil {
		t.Error("expected error for pointer to non-struct")
	}
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
		ID string `mask:"secret,hash"`
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

func TestRedactSliceOfStructs(t *testing.T) {
	m := New()
	users := []customer{
		{Name: "Alice", Email: "alice@example.com", SSN: "111-11-1111"},
		{Name: "Bob", Email: "bob@example.com", SSN: "222-22-2222"},
	}

	masked, err := Redact(m, users)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(masked) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(masked))
	}
	if masked[0].Email != "[REDACTED]" {
		t.Errorf("Email[0] = %q, want [REDACTED]", masked[0].Email)
	}
	if masked[1].Email != "[REDACTED]" {
		t.Errorf("Email[1] = %q, want [REDACTED]", masked[1].Email)
	}
	if users[0].Email != "alice@example.com" {
		t.Error("original slice was mutated")
	}
}

func TestRedactSliceOfPointers(t *testing.T) {
	m := New()
	users := []*customer{
		{Name: "Alice", Email: "alice@example.com", SSN: "111-11-1111"},
		{Name: "Bob", Email: "bob@example.com", SSN: "222-22-2222"},
	}

	masked, err := Redact(m, users)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(masked) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(masked))
	}
	if masked[0].Email != "[REDACTED]" {
		t.Errorf("Email[0] = %q, want [REDACTED]", masked[0].Email)
	}
	if masked[1].Email != "[REDACTED]" {
		t.Errorf("Email[1] = %q, want [REDACTED]", masked[1].Email)
	}
}

func TestRedactPointerToStruct(t *testing.T) {
	m := New()
	user := &customer{
		Name:  "Alice",
		Email: "alice@example.com",
		SSN:   "111-11-1111",
	}

	masked, err := Redact(m, user)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if masked.Email != "[REDACTED]" {
		t.Errorf("Email = %q, want [REDACTED]", masked.Email)
	}
	if user.Email != "alice@example.com" {
		t.Error("original pointer was mutated")
	}
}

func TestRedactArrayOfStructs(t *testing.T) {
	m := New()
	users := [2]customer{
		{Name: "Alice", Email: "alice@example.com", SSN: "111-11-1111"},
		{Name: "Bob", Email: "bob@example.com", SSN: "222-22-2222"},
	}

	masked, err := Redact(m, users)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if masked[0].Email != "[REDACTED]" {
		t.Errorf("Email[0] = %q, want [REDACTED]", masked[0].Email)
	}
	if masked[1].Email != "[REDACTED]" {
		t.Errorf("Email[1] = %q, want [REDACTED]", masked[1].Email)
	}
}

func TestRedactNilSlice(t *testing.T) {
	m := New()
	var users []customer

	masked, err := Redact(m, users)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if masked != nil {
		t.Error("nil slice should remain nil")
	}
}

func TestRedactContextWithUsersSlice(t *testing.T) {
	// Context{Users: []User} — the exact use case.
	type User struct {
		Name  string
		Email string `mask:"email"`
		SSN   string `mask:"secret"`
	}
	type Context struct {
		Users []User
	}

	m := New()
	ctx := Context{
		Users: []User{
			{Name: "Alice", Email: "alice@example.com", SSN: "111-11-1111"},
			{Name: "Bob", Email: "bob@example.com", SSN: "222-22-2222"},
		},
	}

	masked, err := Redact(m, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(masked.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(masked.Users))
	}
	if masked.Users[0].Name != "Alice" {
		t.Errorf("Name = %q, want Alice", masked.Users[0].Name)
	}
	if masked.Users[0].Email != "[REDACTED]" {
		t.Errorf("Email = %q, want [REDACTED]", masked.Users[0].Email)
	}
	if masked.Users[0].SSN != "[REDACTED]" {
		t.Errorf("SSN = %q, want [REDACTED]", masked.Users[0].SSN)
	}
	if masked.Users[1].Email != "[REDACTED]" {
		t.Errorf("Email[1] = %q, want [REDACTED]", masked.Users[1].Email)
	}
	// Original must not be mutated.
	if ctx.Users[0].Email != "alice@example.com" {
		t.Error("original Users slice was mutated")
	}
}

func TestRedactNestedPointerField(t *testing.T) {
	type Profile struct {
		Phone string `mask:"phone"`
	}
	type User struct {
		Name    string
		Profile *Profile
	}

	m := New()
	user := User{
		Name:    "Alice",
		Profile: &Profile{Phone: "+1-555-1234"},
	}

	masked, err := Redact(m, user)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if masked.Profile.Phone != "[REDACTED]" {
		t.Errorf("Profile.Phone = %q, want [REDACTED]", masked.Profile.Phone)
	}
	if user.Profile.Phone != "+1-555-1234" {
		t.Error("original pointer was mutated")
	}
}

func TestRedactNestedStructField(t *testing.T) {
	type Address struct {
		Zip string `mask:"secret"`
	}
	type User struct {
		Name    string
		Address Address
	}

	m := New()
	user := User{
		Name:    "Alice",
		Address: Address{Zip: "90210"},
	}

	masked, err := Redact(m, user)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if masked.Address.Zip != "[REDACTED]" {
		t.Errorf("Address.Zip = %q, want [REDACTED]", masked.Address.Zip)
	}
}

func TestRedactNonStructError(t *testing.T) {
	m := New()
	_, err := Redact(m, 42)
	if err == nil {
		t.Error("expected error for int")
	}
	_, err = Redact(m, "hello")
	if err == nil {
		t.Error("expected error for string")
	}
	_, err = Redact(m, map[string]int{"a": 1})
	if err == nil {
		t.Error("expected error for map")
	}
}

func TestCacheSharedAcrossRecursiveCalls(t *testing.T) {
	// Verify that the cache is shared across recursive redactions
	// (slice elements, nested structs, pointer fields).
	type Inner struct {
		Val string `mask:"secret"`
	}
	type Outer struct {
		Items []Inner
	}

	m := New()
	v := Outer{Items: []Inner{{Val: "a"}, {Val: "b"}, {Val: "c"}}}

	_, _ = Redact(m, v)

	// Inner should be cached exactly once (all 3 elements share the cache).
	if _, ok := m.cache.Load(reflect.TypeFor[Inner]()); !ok {
		t.Error("Inner type not cached after recursive redaction")
	}
	if _, ok := m.cache.Load(reflect.TypeFor[Outer]()); !ok {
		t.Error("Outer type not cached")
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

func TestMaskerZeroAndNilGuards(t *testing.T) {
	type rec struct {
		Email string `mask:"email"`
	}
	cases := []struct {
		name string
		m    *Masker
		want error
	}{
		{"nil", nil, ErrNilReceiver},
		{"zero value", &Masker{}, ErrUninitialized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := rec{Email: "a@b.c"}
			if got, err := Redact(tc.m, v); !errors.Is(err, tc.want) || got != (rec{}) {
				t.Errorf("Redact = (%+v, %v), want zero and %v", got, err, tc.want)
			}
			if _, err := tc.m.RedactAny(v); !errors.Is(err, tc.want) {
				t.Errorf("RedactAny err = %v, want %v", err, tc.want)
			}
			if err := tc.m.RedactInPlace(&v); !errors.Is(err, tc.want) {
				t.Errorf("RedactInPlace err = %v, want %v", err, tc.want)
			}
			if v.Email != "a@b.c" {
				t.Errorf("input mutated: %q", v.Email)
			}
			if _, err := tc.m.RedactPII()(v); !errors.Is(err, tc.want) {
				t.Errorf("RedactPII err = %v, want %v", err, tc.want)
			}
			if _, err := tc.m.HashEmails()(v); !errors.Is(err, tc.want) {
				t.Errorf("HashEmails err = %v, want %v", err, tc.want)
			}
			if _, err := Apply(tc.m, v, func(a any) (any, error) { return a, nil }); !errors.Is(err, tc.want) {
				t.Errorf("Apply err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestApplyNilAndBadPolicy(t *testing.T) {
	type rec struct{ A string }
	m := New()
	if _, err := Apply(m, rec{}, nil); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("nil policy err = %v", err)
	}
	bad := func(any) (any, error) { return 42, nil }
	if _, err := Apply(m, rec{}, bad); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("wrong-type policy err = %v", err)
	}
}
