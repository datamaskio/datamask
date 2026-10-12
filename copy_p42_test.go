package datamask

import (
	"errors"
	"reflect"
	"testing"
)

type p42Event struct {
	Name    string
	Payload any
	Extra   map[string]any
	List    []any
}

func p42Profile() cpProfile { return cpProfile{Avatar: "a.png", Email: "ann@example.com"} }

// -- slices and arrays --

func TestSliceBackingArrayClonedOnlyWhenNeeded(t *testing.T) {
	m := New()
	type rows struct {
		Masked []cpProfile
		Plain  []cpPlain
		Ints   []int
	}
	in := rows{
		Masked: []cpProfile{p42Profile()},
		Plain:  []cpPlain{{Label: "x"}},
		Ints:   []int{1, 2},
	}
	got, err := Redact(m, in)
	if err != nil {
		t.Fatal(err)
	}
	if &got.Masked[0] == &in.Masked[0] {
		t.Error("slice with maskable elements must be cloned")
	}
	if &got.Plain[0] != &in.Plain[0] || &got.Ints[0] != &in.Ints[0] {
		t.Error("slices with nothing to mask must share their backing array")
	}
	if in.Masked[0].Email != "ann@example.com" {
		t.Error("input mutated")
	}
	if got.Masked[0].Email == "ann@example.com" {
		t.Error("clone not masked")
	}
}

func TestArraysAreMaskedWithoutTouchingInput(t *testing.T) {
	m := New()
	type holder struct {
		Rows [2]cpProfile
		Ptrs [2]*cpProfile
	}
	in := holder{Rows: [2]cpProfile{p42Profile(), p42Profile()}, Ptrs: [2]*cpProfile{{Email: "p@x.y"}, nil}}
	want := holder{Rows: in.Rows, Ptrs: [2]*cpProfile{{Email: "p@x.y"}, nil}}
	got, err := Redact(m, in)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, want) {
		t.Errorf("input mutated: %+v", in)
	}
	if got.Rows[1].Email == "ann@example.com" || got.Ptrs[0].Email == "p@x.y" || got.Ptrs[1] != nil {
		t.Errorf("got %+v", got)
	}
	// Top-level array.
	arr, err := Redact(m, [1]cpProfile{p42Profile()})
	if err != nil || arr[0].Email == "ann@example.com" {
		t.Errorf("top-level array: (%+v, %v)", arr, err)
	}
}

// -- maps --

func TestMapValuesCopyOnWrite(t *testing.T) {
	m := New()
	type holder struct {
		ByName map[string]cpProfile
		ByPtr  map[string]*cpProfile
		Plain  map[string]int
		Nil    map[string]cpProfile
	}
	shared := &cpProfile{Email: "ptr@example.com"}
	in := holder{
		ByName: map[string]cpProfile{"a": p42Profile()},
		ByPtr:  map[string]*cpProfile{"p": shared, "nil": nil},
		Plain:  map[string]int{"n": 1},
	}
	got, err := Redact(m, in)
	if err != nil {
		t.Fatal(err)
	}
	if in.ByName["a"].Email != "ann@example.com" || shared.Email != "ptr@example.com" {
		t.Error("input mutated")
	}
	if got.ByName["a"].Email == "ann@example.com" || got.ByPtr["p"].Email == "ptr@example.com" {
		t.Errorf("not masked: %+v %+v", got.ByName, got.ByPtr["p"])
	}
	if got.ByPtr["p"] == shared {
		t.Error("pointer value must be cloned")
	}
	if v, ok := got.ByPtr["nil"]; !ok || v != nil {
		t.Error("nil map value must stay nil")
	}
	if reflect.ValueOf(got.ByName).Pointer() == reflect.ValueOf(in.ByName).Pointer() {
		t.Error("masked map must be a new map")
	}
	if reflect.ValueOf(got.Plain).Pointer() != reflect.ValueOf(in.Plain).Pointer() {
		t.Error("map with nothing to mask should be shared")
	}
	if got.Nil != nil {
		t.Error("nil map must stay nil")
	}
}

func TestMapKeysNeverMasked(t *testing.T) {
	m := New()
	got, err := Redact(m, map[string]cpProfile{"ann@example.com": p42Profile()})
	if err != nil {
		t.Fatal(err)
	}
	v, ok := got["ann@example.com"]
	if !ok || v.Email == "ann@example.com" {
		t.Errorf("got %+v", got)
	}
}

func TestTopLevelMapAndNilMap(t *testing.T) {
	m := New()
	s, err := Compile[map[string]cpProfile](m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Redact(map[string]cpProfile{"k": p42Profile()})
	if err != nil || got["k"].Email == "ann@example.com" {
		t.Errorf("(%+v, %v)", got, err)
	}
	var nilMap map[string]cpProfile
	out, err := s.Redact(nilMap)
	if err != nil || out != nil {
		t.Errorf("nil map: (%v, %v)", out, err)
	}
	if _, err := Compile[map[string]chan int](m); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("map of chan err = %v", err)
	}
	if _, err := Compile[map[string]cpBadTag](m); !errors.Is(err, ErrUnknownDataType) {
		t.Errorf("map of bad tag err = %v", err)
	}
}

func TestMapDepthAndCycle(t *testing.T) {
	type tree struct {
		Kids map[string]*tree
		Mail string `mask:"email"`
	}
	leaf := &tree{Mail: "l@x.y"}
	root := &tree{Kids: map[string]*tree{"a": leaf}, Mail: "r@x.y"}
	got, err := Redact(New(), root)
	if err != nil || got.Mail == "r@x.y" || got.Kids["a"].Mail == "l@x.y" {
		t.Fatalf("(%+v, %v)", got, err)
	}
	leaf.Kids = map[string]*tree{"back": root}
	if _, err := Redact(New(), root); !errors.Is(err, ErrCyclicReference) {
		t.Errorf("cycle through map err = %v", err)
	}
	leaf.Kids = nil
	if _, err := Redact(New(WithMaxTraversalDepth(1)), root); !errors.Is(err, ErrMaxDepthExceeded) {
		t.Errorf("depth err = %v", err)
	}
}

// -- interface fields --

func TestInterfaceFieldsWalkedWhenSupported(t *testing.T) {
	m := New()
	prof := p42Profile()
	in := p42Event{
		Name:    "e",
		Payload: prof,
		Extra: map[string]any{
			"ptr":   &cpProfile{Email: "p@x.y"},
			"str":   "plain",
			"num":   7,
			"nil":   nil,
			"slice": []cpProfile{p42Profile()},
		},
		List: []any{prof, &cpProfile{Email: "q@x.y"}, nil, "s", make(chan int)},
	}
	got, err := Redact(m, in)
	if err != nil {
		t.Fatal(err)
	}
	if prof.Email != "ann@example.com" || in.Extra["ptr"].(*cpProfile).Email != "p@x.y" {
		t.Error("input mutated")
	}
	if got.Payload.(cpProfile).Email == "ann@example.com" {
		t.Error("struct in interface not masked")
	}
	if got.Extra["ptr"].(*cpProfile).Email == "p@x.y" || got.Extra["slice"].([]cpProfile)[0].Email == "ann@example.com" {
		t.Errorf("nested dynamic values not masked: %+v", got.Extra)
	}
	if got.Extra["str"] != "plain" || got.Extra["num"] != 7 {
		t.Error("scalars must pass through")
	}
	if v, ok := got.Extra["nil"]; !ok || v != nil {
		t.Error("nil interface must stay nil")
	}
	if got.List[0].(cpProfile).Email == "ann@example.com" || got.List[1].(*cpProfile).Email == "q@x.y" {
		t.Errorf("list not masked: %+v", got.List)
	}
	if got.List[2] != nil || got.List[3] != "s" {
		t.Error("nil / string list elements must pass through")
	}
	if _, ok := got.List[4].(chan int); !ok {
		t.Error("chan must pass through")
	}
}

func TestInterfaceNilAndUnsupportedFields(t *testing.T) {
	m := New()
	for _, in := range []p42Event{
		{},
		{Payload: "text"},
		{Payload: 3.5},
		{Payload: func() {}},
		{Payload: make(chan int)},
	} {
		got, err := Redact(m, in)
		if err != nil {
			t.Errorf("%+v: %v", in.Payload, err)
			continue
		}
		if in.Payload == nil && got.Payload != nil {
			t.Error("nil payload became non-nil")
		}
	}
}

func TestInterfaceHoldingMaskableAndErrors(t *testing.T) {
	m := New()
	type holder struct{ V any }

	got, err := Redact(m, holder{V: okVal{S: "secret"}})
	if err != nil || got.V.(okVal).S != "***" {
		t.Errorf("Maskable in interface: (%+v, %v)", got, err)
	}
	if _, err := Redact(m, holder{V: failVal{S: "x"}}); !errors.Is(err, ErrMaskFailed) {
		t.Errorf("failing Maskable in interface err = %v", err)
	}
	if _, err := Redact(m, holder{V: cpBadTag{X: "s"}}); !errors.Is(err, ErrUnknownDataType) {
		t.Errorf("bad tag in interface err = %v", err)
	}
	if _, err := Redact(m, holder{V: cpKeyless{X: "s"}}); !errors.Is(err, ErrInvalidSchema) {
		t.Errorf("keyless in interface err = %v", err)
	}

	// A field typed as the Maskable interface itself, nil and non-nil.
	type typed struct{ M Maskable }
	if out, err := Redact(m, typed{}); err != nil || out.M != nil {
		t.Errorf("nil Maskable interface: (%+v, %v)", out, err)
	}
	out, err := Redact(m, typed{M: okVal{S: "secret"}})
	if err != nil || out.M.(okVal).S != "***" {
		t.Errorf("Maskable interface field: (%+v, %v)", out, err)
	}
}

func TestInterfaceCycle(t *testing.T) {
	type node struct {
		Mail string `mask:"email"`
		Next any
	}
	n := &node{Mail: "a@x.y"}
	n.Next = n
	if _, err := Redact(New(), n); !errors.Is(err, ErrCyclicReference) {
		t.Errorf("cycle through interface err = %v", err)
	}
}

// -- in place --

func TestRedactInPlaceMapsAndInterfaces(t *testing.T) {
	m := New()
	shared := &cpProfile{Email: "ptr@example.com"}
	type holder struct {
		ByName map[string]cpProfile
		ByPtr  map[string]*cpProfile
		Any    any
		AnyPtr any
		Slice  any
		Nested map[string]any
		Nil    map[string]cpProfile
		NilAny any
	}
	h := &holder{
		ByName: map[string]cpProfile{"a": p42Profile()},
		ByPtr:  map[string]*cpProfile{"p": shared},
		Any:    p42Profile(),
		AnyPtr: &cpProfile{Email: "ap@x.y"},
		Slice:  []cpProfile{p42Profile()},
		Nested: map[string]any{"m": p42Profile(), "s": "plain"},
	}
	anyPtr := h.AnyPtr.(*cpProfile)
	if err := m.RedactInPlace(h); err != nil {
		t.Fatal(err)
	}
	const masked = "[REDACTED]"
	checks := map[string]string{
		"ByName":  h.ByName["a"].Email,
		"ByPtr":   h.ByPtr["p"].Email,
		"Any":     h.Any.(cpProfile).Email,
		"AnyPtr":  h.AnyPtr.(*cpProfile).Email,
		"Slice":   h.Slice.([]cpProfile)[0].Email,
		"Nested":  h.Nested["m"].(cpProfile).Email,
		"shared":  shared.Email,
		"anyPtr0": anyPtr.Email,
	}
	for name, got := range checks {
		if got != masked {
			t.Errorf("%s.Email = %q, want %q", name, got, masked)
		}
	}
	if h.Nested["s"] != "plain" || h.Nil != nil || h.NilAny != nil {
		t.Error("pass-through values changed")
	}
}

func TestRedactInPlaceInterfaceMaskableAndErrors(t *testing.T) {
	m := New()
	type holder struct {
		A any
		M map[string]okVal
	}
	h := &holder{A: okVal{S: "x"}, M: map[string]okVal{"k": {S: "y"}}}
	if err := m.RedactInPlace(h); err != nil || h.A.(okVal).S != "***" || h.M["k"].S != "***" {
		t.Errorf("(%+v, %v)", h, err)
	}
	f := &holder{A: failVal{S: "x"}}
	checkFailClosed(t, m.RedactInPlace(f), true)

	bad := &struct{ A any }{A: cpBadTag{X: "s"}}
	if err := m.RedactInPlace(bad); !errors.Is(err, ErrUnknownDataType) {
		t.Errorf("bad tag in interface err = %v", err)
	}

	type node struct {
		Mail string `mask:"email"`
		Next any
		Kids map[string]*node
	}
	n := &node{Mail: "a@x.y"}
	n.Next = n
	if err := m.RedactInPlace(n); !errors.Is(err, ErrCyclicReference) {
		t.Errorf("interface cycle err = %v", err)
	}
	k := &node{Mail: "b@x.y"}
	k.Kids = map[string]*node{"self": k}
	if err := m.RedactInPlace(k); !errors.Is(err, ErrCyclicReference) {
		t.Errorf("map cycle err = %v", err)
	}
	d := &struct {
		M map[string]map[string]cpProfile
	}{M: map[string]map[string]cpProfile{"a": {"b": p42Profile()}}}
	if err := New(WithMaxTraversalDepth(1)).RedactInPlace(d); !errors.Is(err, ErrMaxDepthExceeded) {
		t.Errorf("map depth err = %v", err)
	}
}

func TestSchemaRedactMapAndInterfaceTypes(t *testing.T) {
	m := New()
	got, err := MustCompile[[]any](m).Redact([]any{p42Profile(), nil, "s"})
	if err != nil || got[0].(cpProfile).Email == "ann@example.com" || got[1] != nil {
		t.Errorf("[]any: (%+v, %v)", got, err)
	}
	g2, err := MustCompile[map[string]any](m).Redact(map[string]any{"a": p42Profile()})
	if err != nil || g2["a"].(cpProfile).Email == "ann@example.com" {
		t.Errorf("map[string]any: (%+v, %v)", g2, err)
	}
}
