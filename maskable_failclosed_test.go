package datamask

import (
	"errors"
	"testing"
)

var errBoom = errors.New("boom")

type failVal struct{ S string }

func (f failVal) Mask() (any, error) { return nil, errBoom }

type failPtr struct{ S string }

func (f *failPtr) Mask() (any, error) { return nil, errBoom }

type wrongType struct{ S string }

func (w wrongType) Mask() (any, error) { return 42, nil }

type nilResult struct{ S string }

func (n nilResult) Mask() (any, error) { return nil, nil }

type okVal struct{ S string }

func (o okVal) Mask() (any, error) { return okVal{S: "***"}, nil }

type holder[F any] struct {
	Name string
	F    F // tag-optional: no mask tag
}

type ptrHolder[F any] struct {
	Name string
	F    *F
}

func checkFailClosed(t *testing.T, err error, wantUser bool) {
	t.Helper()
	if !errors.Is(err, ErrMaskFailed) {
		t.Fatalf("err = %v, want ErrMaskFailed", err)
	}
	if wantUser && !errors.Is(err, errBoom) {
		t.Errorf("err = %v, want it to wrap errBoom", err)
	}
}

func TestMaskableFailClosedRedact(t *testing.T) {
	m := New()

	t.Run("error value receiver", func(t *testing.T) {
		got, err := Redact(m, holder[failVal]{Name: "n", F: failVal{S: "secret"}})
		checkFailClosed(t, err, true)
		if got != (holder[failVal]{}) {
			t.Errorf("got %+v, want zero value", got)
		}
	})
	t.Run("error pointer receiver", func(t *testing.T) {
		got, err := Redact(m, holder[failPtr]{Name: "n", F: failPtr{S: "secret"}})
		checkFailClosed(t, err, true)
		if got != (holder[failPtr]{}) {
			t.Errorf("got %+v, want zero value", got)
		}
	})
	t.Run("wrong type", func(t *testing.T) {
		got, err := Redact(m, holder[wrongType]{F: wrongType{S: "secret"}})
		checkFailClosed(t, err, false)
		if got != (holder[wrongType]{}) {
			t.Errorf("got %+v, want zero value", got)
		}
	})
	t.Run("nil result", func(t *testing.T) {
		_, err := Redact(m, holder[nilResult]{F: nilResult{S: "secret"}})
		checkFailClosed(t, err, false)
	})
	t.Run("nil pointer is skipped", func(t *testing.T) {
		got, err := Redact(m, ptrHolder[failVal]{Name: "n"})
		if err != nil || got.F != nil {
			t.Errorf("got (%+v, %v), want nil ptr and no error", got, err)
		}
	})
	t.Run("top level", func(t *testing.T) {
		got, err := Redact(m, failVal{S: "secret"})
		checkFailClosed(t, err, true)
		if got != (failVal{}) {
			t.Errorf("got %+v, want zero value", got)
		}
	})
	t.Run("top level wrong type", func(t *testing.T) {
		_, err := Redact(m, wrongType{S: "secret"})
		checkFailClosed(t, err, false)
	})
	t.Run("slice element fails", func(t *testing.T) {
		got, err := Redact(m, []holder[failVal]{{F: failVal{S: "secret"}}})
		checkFailClosed(t, err, true)
		if got != nil {
			t.Errorf("got %+v, want nil", got)
		}
	})
	t.Run("nested struct fails", func(t *testing.T) {
		type outer struct{ In holder[failVal] }
		got, err := Redact(m, outer{In: holder[failVal]{F: failVal{S: "secret"}}})
		checkFailClosed(t, err, true)
		if got != (outer{}) {
			t.Errorf("got %+v, want zero value", got)
		}
	})
	t.Run("tagged field", func(t *testing.T) {
		type tagged struct {
			F failVal `mask:"secret"`
		}
		_, err := Redact(m, tagged{F: failVal{S: "secret"}})
		checkFailClosed(t, err, true)
	})
	t.Run("success", func(t *testing.T) {
		got, err := Redact(m, holder[okVal]{F: okVal{S: "secret"}})
		if err != nil || got.F.S != "***" {
			t.Errorf("got (%+v, %v)", got, err)
		}
	})
}

func TestMaskableFailClosedRedactInPlace(t *testing.T) {
	m := New()

	v := &holder[failVal]{Name: "n", F: failVal{S: "secret"}}
	checkFailClosed(t, m.RedactInPlace(v), true)
	if v.F.S != "" {
		t.Errorf("failing field = %q, want zeroed", v.F.S)
	}
	if v.Name != "n" {
		t.Errorf("unrelated field changed: %q", v.Name)
	}

	w := &holder[wrongType]{F: wrongType{S: "secret"}}
	checkFailClosed(t, m.RedactInPlace(w), false)
	if w.F.S != "" {
		t.Errorf("failing field = %q, want zeroed", w.F.S)
	}

	// A failure must not stop other tagged fields from being masked.
	type mixed struct {
		Bad   failVal
		Email string `mask:"email"`
	}
	x := &mixed{Bad: failVal{S: "secret"}, Email: "a@b.c"}
	checkFailClosed(t, m.RedactInPlace(x), true)
	if x.Email == "a@b.c" || x.Bad.S != "" {
		t.Errorf("got %+v, want email masked and Bad zeroed", x)
	}
}

func TestMaskableFailClosedPolicies(t *testing.T) {
	m := New()
	v := holder[failVal]{F: failVal{S: "secret"}}
	if _, err := m.RedactPII()(v); !errors.Is(err, ErrMaskFailed) {
		t.Errorf("RedactPII err = %v", err)
	}
	if _, err := m.HashEmails()(v); !errors.Is(err, ErrMaskFailed) {
		t.Errorf("HashEmails err = %v", err)
	}
}

type embedInner[F any] struct{ F F }

type embedValue[F any] struct {
	embedInner[F]
	Name string
}

type embedPtr[F any] struct {
	*embedInner[F]
	Name string
}

func TestApplyMaskableFieldsEmbedded(t *testing.T) {
	m := New()

	t.Run("embedded value masks promoted field", func(t *testing.T) {
		got, err := Redact(m, embedValue[okVal]{embedInner: embedInner[okVal]{F: okVal{S: "secret"}}})
		if err != nil || got.F.S != "***" {
			t.Errorf("got (%+v, %v)", got, err)
		}
	})
	t.Run("embedded value error propagates", func(t *testing.T) {
		_, err := Redact(m, embedValue[failVal]{embedInner: embedInner[failVal]{F: failVal{S: "secret"}}})
		checkFailClosed(t, err, true)
	})
	t.Run("nil embedded pointer skipped", func(t *testing.T) {
		got, err := Redact(m, embedPtr[failVal]{Name: "n"})
		if err != nil || got.embedInner != nil || got.Name != "n" {
			t.Errorf("got (%+v, %v)", got, err)
		}
	})
	t.Run("embedded pointer error propagates", func(t *testing.T) {
		in := &embedInner[failVal]{F: failVal{S: "secret"}}
		err := m.RedactInPlace(&embedPtr[failVal]{embedInner: in})
		checkFailClosed(t, err, true)
		if in.F.S != "" {
			t.Errorf("embedded field = %q, want zeroed", in.F.S)
		}
	})
	t.Run("unexported and unsettable fields skipped", func(t *testing.T) {
		type hidden struct {
			f failVal //nolint:unused
			N string
		}
		if _, err := Redact(m, hidden{f: failVal{S: "x"}, N: "n"}); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
