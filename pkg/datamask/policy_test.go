package datamask

import (
	"errors"
	"testing"
)

func TestIdentity(t *testing.T) {
	p := Identity()
	in := "hello"
	got, err := p(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != in {
		t.Errorf("Identity() = %v, want %v", got, in)
	}
}

func TestComposeEmpty(t *testing.T) {
	p := Compose()
	in := "hello"
	got, err := p(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != in {
		t.Errorf("Compose() = %v, want %v", got, in)
	}
}

func TestComposeSingle(t *testing.T) {
	upper := Policy(func(v any) (any, error) {
		return RedactValue(v.(string)), nil
	})

	p := Compose(upper)
	got, err := p("hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "[REDACTED]" {
		t.Errorf("Compose(single) = %v, want [REDACTED]", got)
	}
}

func TestComposeOrdering(t *testing.T) {
	// append "A" then "B" — verify left-to-right order
	appendA := Policy(func(v any) (any, error) {
		s := v.(string)
		return s + "A", nil
	})
	appendB := Policy(func(v any) (any, error) {
		s := v.(string)
		return s + "B", nil
	})

	p := Compose(appendA, appendB)
	got, err := p("X")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "XAB" {
		t.Errorf("Compose order: got %q, want %q", got, "XAB")
	}
}

func TestComposeErrorShortCircuits(t *testing.T) {
	errBoom := errors.New("boom")

	appendA := Policy(func(v any) (any, error) {
		return v.(string) + "A", nil
	})
	fail := Policy(func(v any) (any, error) {
		return nil, errBoom
	})
	appendC := Policy(func(v any) (any, error) {
		return v.(string) + "C", nil
	})

	p := Compose(appendA, fail, appendC)
	got, err := p("X")

	if !errors.Is(err, errBoom) {
		t.Errorf("expected error %v, got %v", errBoom, err)
	}
	// got should be nil since the erroring policy returned nil.
	if got != nil {
		t.Errorf("expected nil value on error, got %v", got)
	}
}

func TestComposePreservesInput(t *testing.T) {
	// Policies must not mutate the input seen by later policies.
	// Compose should pass the output of policy N as input to policy N+1.

	appendA := Policy(func(v any) (any, error) {
		return v.(string) + "A", nil
	})
	appendB := Policy(func(v any) (any, error) {
		return v.(string) + "B", nil
	})

	p := Compose(appendA, appendB)

	// First policy appends A, second sees "XA" and appends B.
	got, _ := p("X")
	if got != "XAB" {
		t.Errorf("got %q, want %q", got, "XAB")
	}
}

func TestPolicyAsType(t *testing.T) {
	// Verify that a plain func(v any) (any, error) satisfies the Policy type.
	var p Policy = func(v any) (any, error) {
		return v, nil
	}
	got, err := p("test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "test" {
		t.Errorf("got %v, want test", got)
	}
}
