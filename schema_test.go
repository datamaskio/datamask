package datamask

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/datamaskio/datamask/internal/reflectx"
)

type schemaUser struct {
	Name  string
	Email string `mask:"email"`
	Card  string `mask:"credit-card"`
}

func TestCompileGuards(t *testing.T) {
	if _, err := Compile[schemaUser](nil); !errors.Is(err, ErrNilReceiver) {
		t.Errorf("nil masker err = %v, want ErrNilReceiver", err)
	}
	if _, err := Compile[schemaUser](&Masker{}); !errors.Is(err, ErrUninitialized) {
		t.Errorf("zero masker err = %v, want ErrUninitialized", err)
	}
}

func TestZeroSchemaUninitialized(t *testing.T) {
	var s Schema[schemaUser]
	got, err := s.Redact(schemaUser{Email: "a@b.c"})
	if !errors.Is(err, ErrUninitialized) || got != (schemaUser{}) {
		t.Errorf("Redact = (%+v, %v), want zero and ErrUninitialized", got, err)
	}
	if err := s.RedactInPlace(&schemaUser{}); !errors.Is(err, ErrUninitialized) {
		t.Errorf("RedactInPlace err = %v, want ErrUninitialized", err)
	}
	var nilSchema *Schema[schemaUser]
	if _, err := nilSchema.Redact(schemaUser{}); !errors.Is(err, ErrUninitialized) {
		t.Errorf("nil *Schema err = %v, want ErrUninitialized", err)
	}
}

func TestCompileRejectsBadTags(t *testing.T) {
	m := New()
	type badType struct {
		X string `mask:"hash"`
	}
	type badTransform struct {
		X string `mask:"email,hsah"`
	}
	if _, err := Compile[badType](m); !errors.Is(err, ErrUnknownDataType) {
		t.Errorf("err = %v, want ErrUnknownDataType", err)
	}
	if _, err := Compile[badTransform](m); !errors.Is(err, ErrUnknownTransform) {
		t.Errorf("err = %v, want ErrUnknownTransform", err)
	}
	if _, err := Compile[[]badType](m); !errors.Is(err, ErrUnknownDataType) {
		t.Errorf("slice err = %v, want ErrUnknownDataType", err)
	}
}

func TestCompileUnsupportedKinds(t *testing.T) {
	m := New()
	if _, err := Compile[int](m); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("int err = %v", err)
	}
	if _, err := Compile[map[string]string](m); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("map err = %v", err)
	}
	if _, err := Compile[*int](m); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("*int err = %v", err)
	}
}

func TestMustCompile(t *testing.T) {
	m := New()
	if s := MustCompile[schemaUser](m); s == nil {
		t.Fatal("MustCompile returned nil")
	}
	defer func() {
		if recover() == nil {
			t.Error("MustCompile should panic on error")
		}
	}()
	MustCompile[int](m)
}

func TestSchemaRedact(t *testing.T) {
	m := New()
	s := MustCompile[schemaUser](m)
	in := schemaUser{Name: "Ann", Email: "ann@example.com", Card: "4111111111111111"}
	got, err := s.Redact(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Ann" || got.Email == in.Email || got.Card == in.Card {
		t.Errorf("got %+v", got)
	}
	if in.Email != "ann@example.com" {
		t.Error("input mutated")
	}
	want, _ := Redact(m, in)
	if got != want {
		t.Errorf("Schema.Redact %+v != Redact %+v", got, want)
	}
}

func TestSchemaRedactContainers(t *testing.T) {
	m := New()
	in := []schemaUser{{Email: "a@b.c"}, {Email: "d@e.f"}}
	got, err := MustCompile[[]schemaUser](m).Redact(in)
	if err != nil || got[0].Email == "a@b.c" || got[1].Email == "d@e.f" {
		t.Errorf("slice: (%+v, %v)", got, err)
	}
	p, err := MustCompile[*schemaUser](m).Redact(&schemaUser{Email: "a@b.c"})
	if err != nil || p.Email == "a@b.c" {
		t.Errorf("pointer: (%+v, %v)", p, err)
	}
	// Interface type: resolved from the dynamic value.
	var a any = schemaUser{Email: "a@b.c"}
	out, err := MustCompile[any](m).Redact(a)
	if err != nil || out.(schemaUser).Email == "a@b.c" {
		t.Errorf("any: (%+v, %v)", out, err)
	}
}

func TestSchemaRedactInPlace(t *testing.T) {
	s := MustCompile[schemaUser](New())
	v := &schemaUser{Name: "Ann", Email: "ann@example.com"}
	if err := s.RedactInPlace(v); err != nil {
		t.Fatal(err)
	}
	if v.Email == "ann@example.com" || v.Name != "Ann" {
		t.Errorf("got %+v", v)
	}
	if err := s.RedactInPlace(nil); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("nil err = %v, want ErrInvalidInput", err)
	}
	if err := MustCompile[[]schemaUser](New()).RedactInPlace(&[]schemaUser{}); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("slice err = %v, want ErrUnsupportedType", err)
	}
}

func TestSchemaMaskableFirst(t *testing.T) {
	m := New()
	// Maskable types: Mask() runs instead of the field plan.
	got, err := MustCompile[okVal](m).Redact(okVal{S: "secret"})
	if err != nil || got.S != "***" {
		t.Errorf("got (%+v, %v)", got, err)
	}
	_, err = MustCompile[failVal](m).Redact(failVal{S: "x"})
	if !errors.Is(err, ErrMaskFailed) {
		t.Errorf("err = %v, want ErrMaskFailed", err)
	}
}

func TestSchemaCacheHitReturnsSamePlan(t *testing.T) {
	m := New()
	a := MustCompile[schemaUser](m)
	b := MustCompile[schemaUser](m)
	if a.plan != b.plan {
		t.Error("second Compile did not reuse the cached plan")
	}
	// Redact[T] goes through the same cache.
	if _, err := Redact(m, schemaUser{}); err != nil {
		t.Fatal(err)
	}
	v, _ := m.schemas.Load(reflect.TypeFor[schemaUser]())
	if v.(*compiledSchema) != a.plan {
		t.Error("Redact[T] used a different plan")
	}
}

func TestSchemaCacheIsolatedPerMasker(t *testing.T) {
	a := MustCompile[schemaUser](New())
	b := MustCompile[schemaUser](New())
	if a.plan == b.plan {
		t.Error("Maskers must not share plans")
	}
}

func TestSchemaConcurrentCompile(t *testing.T) {
	m := New()
	var wg sync.WaitGroup
	plans := make([]*compiledSchema, 32)
	for i := range plans {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := MustCompile[schemaUser](m)
			if _, err := s.Redact(schemaUser{Email: "a@b.c"}); err != nil {
				t.Error(err)
			}
			plans[i] = s.plan
		}()
	}
	wg.Wait()
	for _, p := range plans {
		if p != plans[0] {
			t.Fatal("concurrent Compile produced different plans")
		}
	}
}

func TestRedactNilInterface(t *testing.T) {
	got, err := Redact[any](New(), nil)
	if !errors.Is(err, ErrInvalidInput) || got != nil {
		t.Errorf("Redact(nil any) = (%v, %v), want nil and ErrInvalidInput", got, err)
	}
}

// -- P3.2: Validate, Explain, Metadata, Warnings --

func TestSchemaMetadata(t *testing.T) {
	m := New()
	before := time.Now()
	s := MustCompile[schemaUser](m)
	md := s.Metadata()
	if md.TypeName != "schemaUser" || md.MaskerID != m.id || md.Version != Version {
		t.Errorf("metadata = %+v", md)
	}
	if md.CreatedAt.Before(before) || md.CreatedAt.After(time.Now()) {
		t.Errorf("CreatedAt %v outside compile window", md.CreatedAt)
	}
	if other := MustCompile[schemaUser](New()).Metadata(); other.MaskerID == md.MaskerID {
		t.Error("distinct Maskers share an ID")
	}
	// Cached plan keeps its original CreatedAt.
	if again := MustCompile[schemaUser](m).Metadata(); !again.CreatedAt.Equal(md.CreatedAt) {
		t.Error("CreatedAt changed on cache hit")
	}
	if got := (&Schema[schemaUser]{}).Metadata(); got != (SchemaMetadata{}) {
		t.Errorf("zero Schema metadata = %+v", got)
	}
	if got := MustCompile[[]schemaUser](m).Metadata().TypeName; got != "[]datamask.schemaUser" {
		t.Errorf("slice TypeName = %q", got)
	}
}

func TestSchemaExplainGolden(t *testing.T) {
	type contact struct {
		Phone string `mask:"phone,partial"`
	}
	type profile struct {
		Name    string
		Email   string  `mask:"email"`
		SSN     string  `mask:"ssn,hash"`
		Token   *string `mask:"secret,tokenize"`
		Contact contact
	}
	want := "Schema: profile\n" +
		"\n  Email (string)\n    data type: email\n    transform: redact\n" +
		"\n  SSN (string)\n    data type: ssn\n    transform: hash\n" +
		"\n  Token (*string)\n    data type: secret\n    transform: tokenize\n"
	if got := MustCompile[profile](New(WithHashKey("h"), WithTokenizeKey("t"))).Explain(); got != want {
		t.Errorf("Explain mismatch\ngot:\n%s\nwant:\n%s", got, want)
	}
	// Containers explain their element's fields.
	if got := MustCompile[[]schemaUser](New()).Explain(); !strings.HasPrefix(got, "Schema: []datamask.schemaUser\n") ||
		!strings.Contains(got, "  Email (string)\n    data type: email\n") {
		t.Errorf("slice Explain = %q", got)
	}
	if got := (&Schema[profile]{}).Explain(); !strings.Contains(got, "uninitialized") {
		t.Errorf("zero Schema Explain = %q", got)
	}
}

func TestSchemaExplainEmbeddedPathAndMaskable(t *testing.T) {
	type base struct {
		Email string `mask:"email"`
	}
	type child struct {
		base
		ID int
	}
	if got := MustCompile[child](New()).Explain(); !strings.Contains(got, "  base.Email (string)") {
		t.Errorf("embedded path missing: %q", got)
	}
	if got := MustCompile[okVal](New()).Explain(); !strings.Contains(got, "Maskable: Mask() takes precedence") {
		t.Errorf("maskable note missing: %q", got)
	}
}

func TestSchemaWarnings(t *testing.T) {
	type inner struct {
		Any any
	}
	type risky struct {
		Name    string
		Payload any
		Ch      chan int
		Fn      func()
		Ptr     unsafe.Pointer
		List    []any
		Nested  inner
		Safe    okVal
		Masked  Maskable
		hidden  any //nolint:unused
	}
	s := MustCompile[risky](New())
	got := map[string]string{}
	for _, w := range s.Warnings() {
		got[w.FieldPath] = w.Reason
	}
	for _, path := range []string{"risky.Payload", "risky.Ch", "risky.Fn", "risky.Ptr", "risky.List", "risky.Nested.Any"} {
		if got[path] == "" {
			t.Errorf("missing warning for %s; got %v", path, got)
		}
	}
	for _, path := range []string{"risky.Name", "risky.Safe", "risky.Masked", "risky.hidden"} {
		if _, ok := got[path]; ok {
			t.Errorf("unexpected warning for %s", path)
		}
	}
	if !strings.Contains(s.Explain(), "warning: risky.Payload: interface-typed field") {
		t.Error("Explain should list warnings")
	}
	// Returned slice is a copy.
	s.Warnings()[0].Reason = "tampered"
	if s.Warnings()[0].Reason == "tampered" {
		t.Error("Warnings exposes internal state")
	}
	if w := MustCompile[schemaUser](New()).Warnings(); len(w) != 0 {
		t.Errorf("clean struct warnings = %v", w)
	}
	if w := (&Schema[risky]{}).Warnings(); w != nil {
		t.Errorf("zero Schema warnings = %v", w)
	}
}

func TestCompileRejectsTaggedUnexportedField(t *testing.T) {
	type bad struct {
		secret string `mask:"secret"`
	}
	_ = bad{secret: ""}
	_, err := Compile[bad](New())
	if !errors.Is(err, ErrInvalidSchema) {
		t.Errorf("err = %v, want ErrInvalidSchema", err)
	}
}

func TestSchemaValidate(t *testing.T) {
	m := New()
	if err := MustCompile[schemaUser](m).Validate(); err != nil {
		t.Errorf("valid schema: %v", err)
	}
	if err := (&Schema[schemaUser]{}).Validate(); !errors.Is(err, ErrUninitialized) {
		t.Errorf("zero Schema err = %v", err)
	}

	// A corrupted plan is reported, not trusted.
	s := MustCompile[schemaUser](New())
	s.plan.meta = &reflectx.TypeMeta{Fields: []reflectx.FieldMeta{{Path: "Email", DataType: reflectx.DataType(99)}}}
	if err := s.Validate(); !errors.Is(err, ErrInvalidSchema) || !errors.Is(err, ErrUnknownDataType) {
		t.Errorf("bad data type err = %v", err)
	}
	s.plan.meta = &reflectx.TypeMeta{Fields: []reflectx.FieldMeta{{Path: "Email", DataType: reflectx.DataTypeEmail, Transform: reflectx.Transform(99)}}}
	if err := s.Validate(); !errors.Is(err, ErrInvalidSchema) || !errors.Is(err, ErrUnknownTransform) {
		t.Errorf("bad transform err = %v", err)
	}
	s.plan.meta = &reflectx.TypeMeta{Fields: []reflectx.FieldMeta{{Path: "x", DataType: reflectx.DataTypeEmail, Unexported: true}}}
	if err := s.Validate(); !errors.Is(err, ErrInvalidSchema) {
		t.Errorf("unexported err = %v", err)
	}
}

func TestSchemaValidateNestedAndContainers(t *testing.T) {
	type badLeaf struct {
		X string `mask:"hash"`
	}
	type holder struct {
		Items []badLeaf
	}
	type cyclic struct {
		Self *cyclic
		Mail string `mask:"email"`
	}
	m := New()
	// The nested bad tag compiles lazily, so Compile succeeds but Validate catches it.
	s, err := Compile[holder](m)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if err := s.Validate(); !errors.Is(err, ErrInvalidSchema) || !errors.Is(err, ErrUnknownDataType) {
		t.Errorf("nested err = %v, want ErrInvalidSchema wrapping ErrUnknownDataType", err)
	}
	if err := MustCompile[[]cyclic](m).Validate(); err != nil {
		t.Errorf("self-referential type: %v", err)
	}
}

// -- P3.3: keys for hash and tokenize --

func TestCompileRejectsKeylessHashAndTokenize(t *testing.T) {
	type hashed struct {
		ID string `mask:"secret,hash"`
	}
	type tokenized struct {
		ID string `mask:"secret,tokenize"`
	}
	type nested struct {
		In hashed
	}

	_, err := Compile[hashed](New())
	if !errors.Is(err, ErrInvalidSchema) || !strings.Contains(err.Error(), "hashed.ID") || !strings.Contains(err.Error(), "WithHashKey") {
		t.Errorf("hash err = %v, want ErrInvalidSchema naming field and WithHashKey", err)
	}
	_, err = Compile[tokenized](New())
	if !errors.Is(err, ErrInvalidSchema) || !strings.Contains(err.Error(), "tokenized.ID") || !strings.Contains(err.Error(), "WithTokenizeKey") {
		t.Errorf("tokenize err = %v, want ErrInvalidSchema naming field and WithTokenizeKey", err)
	}

	// The other key does not satisfy the requirement.
	if _, err := Compile[hashed](New(WithTokenizeKey("t"))); !errors.Is(err, ErrInvalidSchema) {
		t.Errorf("hash with only tokenize key: err = %v", err)
	}
	if _, err := Compile[tokenized](New(WithHashKey("h"))); !errors.Is(err, ErrInvalidSchema) {
		t.Errorf("tokenize with only hash key: err = %v", err)
	}

	// Keys present: compiles and masks.
	if _, err := Compile[hashed](New(WithHashKey("h"))); err != nil {
		t.Errorf("hash with key: %v", err)
	}
	if _, err := Compile[tokenized](New(WithTokenizeKey("t"))); err != nil {
		t.Errorf("tokenize with key: %v", err)
	}

	// Redact (which compiles) and nested types fail closed too.
	if got, err := Redact(New(), hashed{ID: "x"}); !errors.Is(err, ErrInvalidSchema) || got != (hashed{}) {
		t.Errorf("Redact = (%+v, %v)", got, err)
	}
	if _, err := Redact(New(), nested{In: hashed{ID: "x"}}); !errors.Is(err, ErrInvalidSchema) {
		t.Errorf("nested Redact err = %v", err)
	}
	if err := MustCompile[nested](New()).Validate(); !errors.Is(err, ErrInvalidSchema) {
		t.Errorf("Validate nested err = %v", err)
	}
}

func TestCompileKeylessRedactAndPartialUnaffected(t *testing.T) {
	type plain struct {
		Email string `mask:"email"`
		Phone string `mask:"phone,partial"`
	}
	if _, err := Compile[plain](New()); err != nil {
		t.Errorf("redact/partial without keys: %v", err)
	}
}
