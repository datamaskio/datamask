package reflectx

import (
	"reflect"
	"testing"
)

// -- Test types --

type taggedStruct struct {
	Name  string
	Email string `mask:"email"`
	Phone string `mask:"phone"`
	ssn   string `mask:"secret"` // unexported — should be skipped
}

type embeddedOuter struct {
	ID int
	taggedStruct
}

type nestedOuter struct {
	Addr struct {
		Street string
		Zip    string `mask:"secret"`
	}
}

type pointerInner struct {
	Secret string `mask:"secret"`
}

type outerWithPointer struct {
	Name   string
	Inner  *pointerInner
	Inner2 *pointerInner
}

// -- Walk tests --

func TestWalkPointerToStruct(t *testing.T) {
	v := &taggedStruct{
		Name:  "John",
		Email: "john@example.com",
		Phone: "+1-555-1234",
		ssn:   "123-45-6789",
	}

	fields := []FieldMeta{
		{Index: []int{1}, Transform: TransformRedact},
		{Index: []int{2}, Transform: TransformHash},
		{Index: []int{3}, Transform: TransformRedact}, // unexported — skipped
	}

	var visited []Transform
	Walk(v, fields, func(fv reflect.Value, fm FieldMeta) {
		visited = append(visited, fm.Transform)
	})

	if len(visited) != 2 {
		t.Fatalf("expected 2 exported fields visited, got %d: %v", len(visited), visited)
	}
	if visited[0] != TransformRedact || visited[1] != TransformHash {
		t.Errorf("unexpected visit order: %v", visited)
	}
}

func TestWalkStructDirectly(t *testing.T) {
	v := taggedStruct{
		Name:  "John",
		Email: "john@example.com",
	}

	fields := []FieldMeta{
		{Index: []int{1}, Transform: TransformRedact},
	}

	var visited int
	Walk(v, fields, func(fv reflect.Value, fm FieldMeta) {
		visited++
	})

	if visited != 1 {
		t.Errorf("expected 1 field visited, got %d", visited)
	}
}

func TestWalkNilPointer(t *testing.T) {
	var v *taggedStruct = nil

	fields := []FieldMeta{
		{Index: []int{1}, Transform: TransformRedact},
	}

	var visited int
	Walk(v, fields, func(fv reflect.Value, fm FieldMeta) {
		visited++
	})

	if visited != 0 {
		t.Errorf("expected 0 visits on nil pointer, got %d", visited)
	}
}

func TestWalkSkipsUnexported(t *testing.T) {
	v := &taggedStruct{
		ssn: "123-45-6789",
	}

	fields := []FieldMeta{
		{Index: []int{3}, Transform: TransformRedact}, // unexported field ssn
	}

	var visited int
	Walk(v, fields, func(fv reflect.Value, fm FieldMeta) {
		visited++
	})

	if visited != 0 {
		t.Errorf("expected unexported field to be skipped, got %d visits", visited)
	}
}

func TestWalkInvalidFieldIndex(t *testing.T) {
	v := &taggedStruct{}

	fields := []FieldMeta{
		{Index: []int{99}, Transform: TransformRedact}, // out of range
	}

	// Invalid indices are skipped gracefully (no panic).
	var visited int
	Walk(v, fields, func(fv reflect.Value, fm FieldMeta) {
		visited++
	})

	if visited != 0 {
		t.Errorf("expected invalid index to be skipped, got %d", visited)
	}
}

func TestWalkPanicsOnNonStruct(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for non-struct value")
		}
	}()

	fields := []FieldMeta{{Index: []int{0}, Transform: TransformRedact}}
	Walk(42, fields, func(fv reflect.Value, fm FieldMeta) {})
}

func TestWalkPanicsOnNonStructPointer(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for pointer-to-non-struct")
		}
	}()

	var x int = 42
	fields := []FieldMeta{{Index: []int{0}, Transform: TransformRedact}}
	Walk(&x, fields, func(fv reflect.Value, fm FieldMeta) {})
}

func TestWalkEmbeddedStruct(t *testing.T) {
	v := &embeddedOuter{
		ID: 1,
		taggedStruct: taggedStruct{
			Name:  "Jane",
			Email: "jane@example.com",
		},
	}

	// FieldByIndex for embedded struct: Index is the path through the struct
	// hierarchy. For embeddedOuter.taggedStruct.Email:
	//   Index[0] = 1 (taggedStruct field in embeddedOuter)
	//   Index[1] = 1 (Email field in taggedStruct)
	fields := []FieldMeta{
		{Index: []int{1, 1}, Transform: TransformRedact},
		{Index: []int{1, 2}, Transform: TransformHash},
	}

	var visited []Transform
	Walk(v, fields, func(fv reflect.Value, fm FieldMeta) {
		visited = append(visited, fm.Transform)
	})

	if len(visited) != 2 {
		t.Fatalf("expected 2 fields visited on embedded struct, got %d: %v", len(visited), visited)
	}
}

func TestWalkNestedStruct(t *testing.T) {
	v := &nestedOuter{}
	v.Addr.Zip = "90210"

	fields := []FieldMeta{
		{Index: []int{0, 1}, Transform: TransformRedact}, // Addr.Zip
	}

	var visited int
	Walk(v, fields, func(fv reflect.Value, fm FieldMeta) {
		visited++
		if fv.String() != "90210" {
			t.Errorf("expected 90210, got %s", fv.String())
		}
	})

	if visited != 1 {
		t.Errorf("expected 1 nested field visited, got %d", visited)
	}
}

func TestWalkNilPointerField(t *testing.T) {
	v := &outerWithPointer{
		Name:   "Test",
		Inner:  nil, // nil pointer — should be skipped
		Inner2: &pointerInner{Secret: "sauce"},
	}

	fields := []FieldMeta{
		{Index: []int{1, 0}, Transform: TransformRedact}, // Inner.Secret (nil)
		{Index: []int{2, 0}, Transform: TransformRedact}, // Inner2.Secret (present)
	}

	var visited int
	Walk(v, fields, func(fv reflect.Value, fm FieldMeta) {
		visited++
	})

	if visited != 1 {
		t.Errorf("expected 1 visit (nil pointer fields skipped), got %d", visited)
	}
}

// -- Benchmarks --

func BenchmarkWalk(b *testing.B) {
	v := &taggedStruct{
		Name:  "John",
		Email: "john@example.com",
		Phone: "+1-555-1234",
	}
	fields := []FieldMeta{
		{Index: []int{1}, Transform: TransformRedact},
		{Index: []int{2}, Transform: TransformRedact},
	}

	b.ResetTimer()
	for b.Loop() {
		Walk(v, fields, func(fv reflect.Value, fm FieldMeta) {
			_ = fv.String()
		})
	}
}
