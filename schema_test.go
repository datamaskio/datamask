package datamask

import (
	"errors"
	"reflect"
	"sync"
	"testing"
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
