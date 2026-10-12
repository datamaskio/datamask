package datamask

import (
	"errors"
	"reflect"
	"testing"
)

type cpProfile struct {
	Avatar string
	Email  string `mask:"email"`
}

type cpPlain struct {
	Label string
	Tags  []string
}

type cpUser struct {
	Name    string
	Profile *cpProfile
	Plain   *cpPlain
	Nested  cpProfile
	Orders  []cpProfile
}

func cpFixture() cpUser {
	return cpUser{
		Name:    "Ann",
		Profile: &cpProfile{Avatar: "a.png", Email: "ann@example.com"},
		Plain:   &cpPlain{Label: "x", Tags: []string{"t"}},
		Nested:  cpProfile{Email: "n@example.com"},
		Orders:  []cpProfile{{Email: "o1@example.com"}, {Email: "o2@example.com"}},
	}
}

func TestImmutableInputNeverModified(t *testing.T) {
	m := New()
	in := cpFixture()
	want := cpFixture()

	got, err := Redact(m, in)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, want) {
		t.Errorf("input mutated:\n got %+v\nwant %+v", in, want)
	}
	if got.Profile.Email == "ann@example.com" || got.Nested.Email == "n@example.com" || got.Orders[0].Email == "o1@example.com" {
		t.Errorf("output not masked: %+v", got)
	}
	if got.Profile == in.Profile {
		t.Error("masked pointer target must be a clone")
	}
	if &got.Orders[0] == &in.Orders[0] {
		t.Error("masked slice must not share the backing array")
	}
	if got.Profile.Avatar != "a.png" {
		t.Error("untagged field inside a cloned struct must be preserved")
	}
}

func TestImmutableUnmaskedSubtreesShared(t *testing.T) {
	m := New()
	in := cpFixture()
	got, err := Redact(m, in)
	if err != nil {
		t.Fatal(err)
	}
	if got.Plain != in.Plain {
		t.Error("pointer to a type with nothing to mask should be shared")
	}

	type withTags struct {
		Tags []string
		Nums [3]int
		N    *int
	}
	n := 1
	src := withTags{Tags: []string{"a"}, N: &n}
	out, err := Redact(m, src)
	if err != nil {
		t.Fatal(err)
	}
	if &out.Tags[0] != &src.Tags[0] || out.N != src.N {
		t.Error("slices and pointers with nothing to mask should be shared")
	}
}

func TestImmutableNilStaysNil(t *testing.T) {
	m := New()
	got, err := Redact(m, cpUser{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Profile != nil || got.Plain != nil || got.Orders != nil {
		t.Errorf("nil fields must stay nil: %+v", got)
	}
	var nilProfile *cpProfile
	p, err := Redact(m, nilProfile)
	if err != nil || p != nil {
		t.Errorf("nil pointer: (%v, %v)", p, err)
	}
}

type cpNode struct {
	Secret string `mask:"secret"`
	Next   *cpNode
}

func TestCycleDetected(t *testing.T) {
	m := New()

	self := &cpNode{Secret: "s"}
	self.Next = self
	got, err := Redact(m, self)
	if !errors.Is(err, ErrCyclicReference) || got != nil {
		t.Errorf("self cycle: (%v, %v)", got, err)
	}

	a := &cpNode{Secret: "a"}
	b := &cpNode{Secret: "b", Next: a}
	a.Next = b
	if _, err := Redact(m, a); !errors.Is(err, ErrCyclicReference) {
		t.Errorf("two-node cycle err = %v", err)
	}
	if a.Secret != "a" || b.Secret != "b" {
		t.Error("input mutated while detecting cycle")
	}

	// Cycle reached through a struct value that holds the pointer.
	type holder struct{ Head *cpNode }
	if _, err := Redact(m, holder{Head: a}); !errors.Is(err, ErrCyclicReference) {
		t.Errorf("nested cycle err = %v", err)
	}
	// And through a slice.
	if _, err := Redact(m, []*cpNode{a}); !errors.Is(err, ErrCyclicReference) {
		t.Errorf("slice cycle err = %v", err)
	}
}

func TestDiamondIsNotACycle(t *testing.T) {
	m := New()
	shared := &cpProfile{Avatar: "s.png", Email: "s@example.com"}
	type diamond struct {
		Left  *cpProfile
		Right *cpProfile
	}
	in := diamond{Left: shared, Right: shared}
	got, err := Redact(m, in)
	if err != nil {
		t.Fatalf("diamond must not error: %v", err)
	}
	if got.Left.Email == "s@example.com" || got.Right.Email == "s@example.com" {
		t.Errorf("both branches must be masked: %+v %+v", got.Left, got.Right)
	}
	if got.Left == got.Right {
		t.Error("shared references are cloned independently (ADR-0032)")
	}
	if shared.Email != "s@example.com" {
		t.Error("shared target mutated")
	}

	// The same pointer repeated in a slice is also fine.
	out, err := Redact(m, []*cpProfile{shared, shared})
	if err != nil || out[0].Email == "s@example.com" || out[1].Email == "s@example.com" {
		t.Errorf("slice diamond: (%+v, %v)", out, err)
	}
}

func cpChain(n int) *cpNode {
	var head *cpNode
	for range n {
		head = &cpNode{Secret: "s", Next: head}
	}
	return head
}

func TestDepthLimit(t *testing.T) {
	if _, err := Redact(New(), cpChain(50)); err != nil {
		t.Errorf("chain of 50 under default limit: %v", err)
	}

	got, err := Redact(New(), cpChain(150))
	if !errors.Is(err, ErrMaxDepthExceeded) || got != nil {
		t.Errorf("chain of 150: (%v, %v), want ErrMaxDepthExceeded", got, err)
	}

	m := New(WithMaxTraversalDepth(3))
	if _, err := Redact(m, cpChain(3)); err != nil {
		t.Errorf("chain of 3 with limit 3: %v", err)
	}
	if _, err := Redact(m, cpChain(4)); !errors.Is(err, ErrMaxDepthExceeded) {
		t.Errorf("chain of 4 with limit 3: err = %v", err)
	}

	// Non-positive values select the default rather than disabling the limit.
	if d := New(WithMaxTraversalDepth(-5)).cfg.MaxTraversalDepth; d != 100 {
		t.Errorf("negative depth = %d, want default 100", d)
	}

	// Slices count as a level too.
	type deep struct{ Rows [][]cpProfile }
	rows := [][]cpProfile{{{Email: "e@x.y"}}}
	if _, err := Redact(New(WithMaxTraversalDepth(2)), deep{Rows: rows}); !errors.Is(err, ErrMaxDepthExceeded) {
		t.Errorf("slice depth err = %v", err)
	}
}

func TestRedactInPlaceMutatesByContract(t *testing.T) {
	m := New()
	u := cpFixture()
	profile, plain := u.Profile, u.Plain
	orders := u.Orders
	if err := m.RedactInPlace(&u); err != nil {
		t.Fatal(err)
	}
	if u.Name != "Ann" || u.Profile.Avatar != "a.png" {
		t.Errorf("untagged fields changed: %+v", u)
	}
	for name, got := range map[string]string{
		"Nested":    u.Nested.Email,
		"Profile":   u.Profile.Email,
		"Orders[0]": u.Orders[0].Email,
		"Orders[1]": u.Orders[1].Email,
	} {
		if got != "[REDACTED]" {
			t.Errorf("%s.Email = %q, want masked in place", name, got)
		}
	}
	// Mutation is by contract: the same pointer targets and backing array.
	if u.Profile != profile || u.Plain != plain || &u.Orders[0] != &orders[0] {
		t.Error("RedactInPlace must reuse the existing pointer targets and backing array")
	}
	if profile.Email != "[REDACTED]" || orders[1].Email != "[REDACTED]" {
		t.Error("shared data should be visible as masked through the original references")
	}
}

func TestRedactInPlaceCycleAndDepth(t *testing.T) {
	m := New()
	self := &cpNode{Secret: "s"}
	self.Next = self
	if err := m.RedactInPlace(self); !errors.Is(err, ErrCyclicReference) {
		t.Errorf("cycle err = %v", err)
	}
	if err := New().RedactInPlace(cpChain(150)); !errors.Is(err, ErrMaxDepthExceeded) {
		t.Errorf("depth err = %v", err)
	}
	if err := New().RedactInPlace(cpChain(50)); err != nil {
		t.Errorf("chain of 50: %v", err)
	}
	// Diamond is fine in place too.
	shared := &cpProfile{Email: "s@x.y"}
	type diamond struct{ A, B *cpProfile }
	d := &diamond{A: shared, B: shared}
	if err := m.RedactInPlace(d); err != nil || shared.Email != "[REDACTED]" {
		t.Errorf("diamond: err=%v email=%q", err, shared.Email)
	}
}

type countMask struct{ S string }

var countMaskCalls int

func (c countMask) Mask() (any, error) {
	countMaskCalls++
	return countMask{S: "***"}, nil
}

func TestMaskCalledOncePerField(t *testing.T) {
	type holder struct {
		Direct countMask
		Slice  []countMask
	}
	m := New()

	countMaskCalls = 0
	got, err := Redact(m, holder{Direct: countMask{"a"}, Slice: []countMask{{"b"}, {"c"}}})
	if err != nil || got.Direct.S != "***" || got.Slice[1].S != "***" {
		t.Fatalf("Redact = (%+v, %v)", got, err)
	}
	if countMaskCalls != 3 {
		t.Errorf("Redact called Mask %d times, want 3", countMaskCalls)
	}

	countMaskCalls = 0
	h := &holder{Direct: countMask{"a"}, Slice: []countMask{{"b"}, {"c"}}}
	if err := m.RedactInPlace(h); err != nil || h.Direct.S != "***" || h.Slice[0].S != "***" {
		t.Fatalf("RedactInPlace = (%+v, %v)", h, err)
	}
	if countMaskCalls != 3 {
		t.Errorf("RedactInPlace called Mask %d times, want 3", countMaskCalls)
	}
}

// -- error propagation from nested types (fail closed) --

type cpBadTag struct {
	X string `mask:"hash"` // transform-only tag: ErrUnknownDataType
}

type cpKeyless struct {
	X string `mask:"secret,hash"` // needs WithHashKey
}

func TestNestedCompileErrorsPropagate(t *testing.T) {
	type viaPtr struct{ In *cpBadTag }
	type viaSlice struct{ In []cpBadTag }
	type viaArray struct{ In [1]cpBadTag }
	type viaStruct struct{ In cpBadTag }
	type keylessPtr struct{ In *cpKeyless }
	type keylessSlice struct{ In []cpKeyless }
	type keylessArray struct{ In [1]cpKeyless }

	cases := []struct {
		name string
		in   any
		want error
	}{
		{"bad tag via pointer", viaPtr{In: &cpBadTag{X: "s"}}, ErrUnknownDataType},
		{"bad tag via slice", viaSlice{In: []cpBadTag{{X: "s"}}}, ErrUnknownDataType},
		{"bad tag via array", viaArray{In: [1]cpBadTag{{X: "s"}}}, ErrUnknownDataType},
		{"bad tag via struct", viaStruct{In: cpBadTag{X: "s"}}, ErrUnknownDataType},
		{"keyless via pointer", keylessPtr{In: &cpKeyless{X: "s"}}, ErrInvalidSchema},
		{"keyless via slice", keylessSlice{In: []cpKeyless{{X: "s"}}}, ErrInvalidSchema},
		{"keyless via array", keylessArray{In: [1]cpKeyless{{X: "s"}}}, ErrInvalidSchema},
		// Top-level containers and pointers hit the same checks in the engine.
		{"top-level pointer", &cpBadTag{X: "s"}, ErrUnknownDataType},
		{"top-level slice", []cpBadTag{{X: "s"}}, ErrUnknownDataType},
		{"top-level array", [1]cpKeyless{{X: "s"}}, ErrInvalidSchema},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			got, err := m.RedactAny(tc.in)
			if !errors.Is(err, tc.want) {
				t.Errorf("RedactAny err = %v, want %v", err, tc.want)
			}
			if got != nil {
				t.Errorf("RedactAny returned %+v alongside an error", got)
			}
		})
	}

	// The same nested types must fail in place too, where they hold a struct.
	inPlace := []struct {
		name string
		in   any
		want error
	}{
		{"bad tag via pointer", &viaPtr{In: &cpBadTag{X: "s"}}, ErrUnknownDataType},
		{"bad tag via slice", &viaSlice{In: []cpBadTag{{X: "s"}}}, ErrUnknownDataType},
		{"bad tag via array", &viaArray{In: [1]cpBadTag{{X: "s"}}}, ErrUnknownDataType},
		{"bad tag via struct", &viaStruct{In: cpBadTag{X: "s"}}, ErrUnknownDataType},
		{"keyless via pointer", &keylessPtr{In: &cpKeyless{X: "s"}}, ErrInvalidSchema},
		{"keyless via slice", &keylessSlice{In: []cpKeyless{{X: "s"}}}, ErrInvalidSchema},
	}
	for _, tc := range inPlace {
		t.Run("in place "+tc.name, func(t *testing.T) {
			if err := New().RedactInPlace(tc.in); !errors.Is(err, tc.want) {
				t.Errorf("RedactInPlace err = %v, want %v", err, tc.want)
			}
		})
	}
}

// -- Maskable elements in place --

func TestRedactInPlaceMaskableElements(t *testing.T) {
	m := New()

	t.Run("slice of Maskable values", func(t *testing.T) {
		type h struct{ Items []okVal }
		v := &h{Items: []okVal{{S: "a"}, {S: "b"}}}
		if err := m.RedactInPlace(v); err != nil {
			t.Fatal(err)
		}
		if v.Items[0].S != "***" || v.Items[1].S != "***" {
			t.Errorf("got %+v", v.Items)
		}
	})

	t.Run("array of Maskable values", func(t *testing.T) {
		type h struct{ Items [2]okVal }
		v := &h{Items: [2]okVal{{S: "a"}, {S: "b"}}}
		if err := m.RedactInPlace(v); err != nil {
			t.Fatal(err)
		}
		if v.Items[0].S != "***" || v.Items[1].S != "***" {
			t.Errorf("got %+v", v.Items)
		}
	})

	t.Run("pointer to Maskable struct in a slice", func(t *testing.T) {
		type h struct{ Items []*okVal }
		v := &h{Items: []*okVal{{S: "a"}, nil}}
		if err := m.RedactInPlace(v); err != nil {
			t.Fatal(err)
		}
		if v.Items[0].S != "***" || v.Items[1] != nil {
			t.Errorf("got %+v", v.Items)
		}
	})

	t.Run("failing slice element is zeroed and reported", func(t *testing.T) {
		type h struct {
			Items []failVal
			Email string `mask:"email"`
		}
		v := &h{Items: []failVal{{S: "a"}, {S: "b"}}, Email: "a@b.c"}
		err := m.RedactInPlace(v)
		checkFailClosed(t, err, true)
		if v.Items[0].S != "" || v.Items[1].S != "" {
			t.Errorf("failing elements = %+v, want zeroed", v.Items)
		}
		if v.Email == "a@b.c" {
			t.Error("a Maskable failure must not stop other fields being masked")
		}
	})

	t.Run("failing wrong-type element", func(t *testing.T) {
		type h struct{ Items [1]wrongType }
		v := &h{Items: [1]wrongType{{S: "a"}}}
		checkFailClosed(t, m.RedactInPlace(v), false)
		if v.Items[0].S != "" {
			t.Errorf("got %+v, want zeroed", v.Items)
		}
	})
}

func TestRedactInPlaceArraysAndNilContainers(t *testing.T) {
	m := New()
	type h struct {
		Rows  [2]cpProfile
		Ptrs  [2]*cpProfile
		Nil   *cpProfile
		Empty []cpProfile
	}
	v := &h{
		Rows: [2]cpProfile{{Email: "a@b.c"}, {Email: "d@e.f"}},
		Ptrs: [2]*cpProfile{{Email: "g@h.i"}, nil},
	}
	if err := m.RedactInPlace(v); err != nil {
		t.Fatal(err)
	}
	if v.Rows[0].Email != "[REDACTED]" || v.Rows[1].Email != "[REDACTED]" || v.Ptrs[0].Email != "[REDACTED]" {
		t.Errorf("got %+v", v)
	}
	if v.Ptrs[1] != nil || v.Nil != nil || v.Empty != nil {
		t.Error("nil containers must stay nil")
	}
}

func TestRedactInPlaceDepthThroughSlices(t *testing.T) {
	type deep struct{ Rows [][]cpProfile }
	v := &deep{Rows: [][]cpProfile{{{Email: "e@x.y"}}}}
	if err := New(WithMaxTraversalDepth(2)).RedactInPlace(v); !errors.Is(err, ErrMaxDepthExceeded) {
		t.Errorf("err = %v, want ErrMaxDepthExceeded", err)
	}
	if err := New().RedactInPlace(v); err != nil || v.Rows[0][0].Email != "[REDACTED]" {
		t.Errorf("default limit: err=%v rows=%+v", err, v.Rows)
	}
}

// -- the engine on unusual inputs --

func TestRedactEngineEdgeCases(t *testing.T) {
	m := New()

	t.Run("unsupported top-level kind", func(t *testing.T) {
		if _, err := m.RedactAny(42); err == nil {
			t.Error("expected an error for an int")
		}
		if _, err := m.RedactAny(make(chan int)); err == nil {
			t.Error("expected an error for a chan")
		}
	})
	t.Run("nil slice and empty slice", func(t *testing.T) {
		var nilS []cpProfile
		got, err := Redact(m, nilS)
		if err != nil || got != nil {
			t.Errorf("nil slice: (%v, %v)", got, err)
		}
		got, err = Redact(m, []cpProfile{})
		if err != nil || got == nil || len(got) != 0 {
			t.Errorf("empty slice: (%v, %v)", got, err)
		}
	})
	t.Run("array depth limit", func(t *testing.T) {
		in := [1][1]cpProfile{{{Email: "a@b.c"}}}
		if _, err := Redact(New(WithMaxTraversalDepth(1)), in); !errors.Is(err, ErrMaxDepthExceeded) {
			t.Errorf("err = %v, want ErrMaxDepthExceeded", err)
		}
	})
	t.Run("slice element Maskable failure", func(t *testing.T) {
		_, err := Redact(m, []failVal{{S: "a"}})
		checkFailClosed(t, err, true)
	})
	t.Run("pointer to Maskable failure", func(t *testing.T) {
		_, err := Redact(m, &failVal{S: "a"})
		checkFailClosed(t, err, true)
	})
	t.Run("touches caches the answer", func(t *testing.T) {
		a, err1 := m.touches(reflect.TypeFor[cpUser]())
		b, err2 := m.touches(reflect.TypeFor[cpUser]())
		if err1 != nil || err2 != nil || !a || !b {
			t.Errorf("touches = (%v,%v), errs %v %v", a, b, err1, err2)
		}
		if c, _ := m.touches(reflect.TypeFor[cpPlain]()); c {
			t.Error("cpPlain has nothing to mask")
		}
		if c, _ := m.touches(reflect.TypeFor[int]()); c {
			t.Error("int has nothing to mask")
		}
	})
	t.Run("touches follows self-referential types", func(t *testing.T) {
		type plainNode struct {
			Name string
			Next *plainNode
		}
		if c, err := m.touches(reflect.TypeFor[plainNode]()); err != nil || c {
			t.Errorf("plainNode touches = (%v, %v), want false", c, err)
		}
		if c, err := m.touches(reflect.TypeFor[cpNode]()); err != nil || !c {
			t.Errorf("cpNode touches = (%v, %v), want true", c, err)
		}
		// A mask field only reachable through a cycle is still found.
		type a struct{ B *cpBackRef }
		if c, err := m.touches(reflect.TypeFor[a]()); err != nil || !c {
			t.Errorf("indirect touches = (%v, %v), want true", c, err)
		}
	})
	t.Run("touches reports compile errors", func(t *testing.T) {
		if _, err := m.touches(reflect.TypeFor[cpBadTag]()); !errors.Is(err, ErrUnknownDataType) {
			t.Errorf("err = %v", err)
		}
	})
}

type cpBackRef struct {
	Back *cpBackRef
	Peer *cpBackTarget
}

type cpBackTarget struct {
	Back  *cpBackRef
	Email string `mask:"email"`
}
