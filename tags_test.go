package datamask

import (
	"errors"
	"reflect"
	"testing"

	"github.com/datamaskio/datamask/internal/reflectx"
)

// -- Test types for tag parsing --

type simpleStruct struct {
	Name  string
	Email string `mask:"email"`
	Phone string `mask:"phone"`
	ssn   string `mask:"secret"` // unexported — still discovered in type walk
}

type untaggedStruct struct {
	Name  string
	Email string
}

type optOutStruct struct {
	Name  string
	Email string `mask:"-"`
	Phone string `mask:"phone"`
}

type mixedStrategy struct {
	Name  string
	Email string `mask:"email"`           // → DataTypeEmail, TransformRedact
	Token string `mask:"email,hash"`      // → DataTypeEmail, TransformHash
	Alias string `mask:"secret,tokenize"` // → DataTypeSecret, TransformTokenize
	Phone string `mask:"phone,partial"`   // → DataTypePhone, TransformPartial
	SSN   string `mask:"ssn"`             // → DataTypeSSN, TransformRedact
	JWT   string `mask:"jwt"`             // → DataTypeJWT, TransformRedact
}

type caseInsensitive struct {
	Email string `mask:"EMAIL"`
	Phone string `mask:"Phone"`
}

type embeddedParent struct {
	ID    int
	Inner simpleStruct
}

type anonymousEmbed struct {
	ID int
	simpleStruct
}

type pointerField struct {
	Name  string `mask:"secret"`
	Inner *simpleStruct
}

// -- Tests --

func TestParseTagsSimple(t *testing.T) {
	meta, err := parseTags(reflect.TypeFor[simpleStruct]())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(meta.Fields) != 3 {
		t.Fatalf("expected 3 tagged fields (including unexported), got %d", len(meta.Fields))
	}

	findField(t, meta.Fields, []int{1}, DataTypeEmail, TransformRedact)  // Email
	findField(t, meta.Fields, []int{2}, DataTypePhone, TransformRedact)  // Phone
	findField(t, meta.Fields, []int{3}, DataTypeSecret, TransformRedact) // ssn
}

func TestParseTagsUntaggedStruct(t *testing.T) {
	meta, err := parseTags(reflect.TypeFor[untaggedStruct]())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(meta.Fields) != 0 {
		t.Errorf("expected 0 fields for untagged struct, got %d", len(meta.Fields))
	}
}

func TestParseTagsOptOut(t *testing.T) {
	meta, err := parseTags(reflect.TypeFor[optOutStruct]())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(meta.Fields) != 1 {
		t.Fatalf("expected 1 field (mask:\"-\" excluded), got %d", len(meta.Fields))
	}
	findField(t, meta.Fields, []int{2}, DataTypePhone, TransformRedact) // Phone
}

func TestParseTagsMixedStrategies(t *testing.T) {
	meta, err := parseTags(reflect.TypeFor[mixedStrategy]())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		index     []int
		dataType  DataType
		transform Transform
	}{
		{[]int{1}, DataTypeEmail, TransformRedact}, // Email: mask:"email"
		{[]int{2}, DataTypeEmail, TransformHash},   // Token: mask:"email,hash"
		{[]int{3}, DataTypeSecret, TransformTokenize},
		{[]int{4}, DataTypePhone, TransformPartial}, // Phone: mask:"phone,partial"
		{[]int{5}, DataTypeSSN, TransformRedact},    // SSN: mask:"ssn"
		{[]int{6}, DataTypeJWT, TransformRedact},    // JWT: mask:"jwt"
	}

	for _, tt := range tests {
		findFieldFull(t, meta.Fields, tt.index, tt.dataType, tt.transform)
	}
}

func TestParseTagsRejectsTransformOnly(t *testing.T) {
	for _, tag := range []string{"hash", "tokenize", "partial", "hash,redact", "", ",hash"} {
		_, _, err := parseTagValue(tag)
		if !errors.Is(err, ErrUnknownDataType) {
			t.Errorf("tag %q: err = %v, want ErrUnknownDataType", tag, err)
		}
	}
}

func TestParseTagValue(t *testing.T) {
	tests := []struct {
		tag  string
		dt   DataType
		tr   Transform
		want error
	}{
		{"email", DataTypeEmail, TransformRedact, nil},
		{" email , hash ", DataTypeEmail, TransformHash, nil},
		{"email,hash,key=value", DataTypeEmail, TransformHash, nil},
		{"email,hash=x", DataTypeEmail, TransformHash, nil},
		{"email,hsah", 0, 0, ErrUnknownTransform},
		{"email,", 0, 0, ErrUnknownTransform},
	}
	for _, tt := range tests {
		dt, tr, err := parseTagValue(tt.tag)
		if !errors.Is(err, tt.want) {
			t.Errorf("tag %q: err = %v, want %v", tt.tag, err, tt.want)
			continue
		}
		if err == nil && (dt != tt.dt || tr != tt.tr) {
			t.Errorf("tag %q: got (%v,%v), want (%v,%v)", tt.tag, dt, tr, tt.dt, tt.tr)
		}
	}
}

func TestParseTagsUnknownDataType(t *testing.T) {
	type bad struct {
		X string `mask:"bogus"`
	}
	_, err := parseTags(reflect.TypeFor[bad]())
	if err == nil {
		t.Fatal("expected error for unknown data type")
	}
}

func TestParseTagsUnknownTransform(t *testing.T) {
	type bad struct {
		X string `mask:"email,encrypt"`
	}
	_, err := parseTags(reflect.TypeFor[bad]())
	if err == nil {
		t.Fatal("expected error for unknown transform")
	}
}

func TestParseTagsCaseInsensitive(t *testing.T) {
	meta, err := parseTags(reflect.TypeFor[caseInsensitive]())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(meta.Fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(meta.Fields))
	}
	findField(t, meta.Fields, []int{0}, DataTypeEmail, TransformRedact)
	findField(t, meta.Fields, []int{1}, DataTypePhone, TransformRedact)
}

func TestParseTagsEmbeddedStruct(t *testing.T) {
	meta, err := parseTags(reflect.TypeFor[anonymousEmbed]())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(meta.Fields) != 3 {
		t.Fatalf("expected 3 promoted tagged fields, got %d", len(meta.Fields))
	}
	findField(t, meta.Fields, []int{1, 1}, DataTypeEmail, TransformRedact)  // promoted Email
	findField(t, meta.Fields, []int{1, 2}, DataTypePhone, TransformRedact)  // promoted Phone
	findField(t, meta.Fields, []int{1, 3}, DataTypeSecret, TransformRedact) // promoted ssn
}

func TestParseTagsNestedStruct(t *testing.T) {
	meta, err := parseTags(reflect.TypeFor[embeddedParent]())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(meta.Fields) != 0 {
		t.Errorf("expected 0 fields (non-anonymous nested struct not walked), got %d", len(meta.Fields))
	}
}

func TestParseTagsPointerField(t *testing.T) {
	meta, err := parseTags(reflect.TypeFor[pointerField]())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(meta.Fields) < 1 {
		t.Fatalf("expected at least 1 field (Name), got %d", len(meta.Fields))
	}
	findField(t, meta.Fields, []int{0}, DataTypeSecret, TransformRedact) // Name
}

func TestParseTagsNonStruct(t *testing.T) {
	meta, err := parseTags(reflect.TypeFor[int]())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(meta.Fields) != 0 {
		t.Errorf("expected 0 fields for non-struct type, got %d", len(meta.Fields))
	}
}

func TestParseTagsPointerToStruct(t *testing.T) {
	meta, err := parseTags(reflect.TypeOf(&simpleStruct{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(meta.Fields) != 3 {
		t.Fatalf("expected 3 fields via pointer deref, got %d", len(meta.Fields))
	}
}

// -- Helpers --

func findField(t *testing.T, fields []reflectx.FieldMeta, wantIndex []int, wantDataType DataType, wantTransform Transform) {
	t.Helper()
	findFieldFull(t, fields, wantIndex, wantDataType, wantTransform)
}

func findFieldFull(t *testing.T, fields []reflectx.FieldMeta, wantIndex []int, wantDataType DataType, wantTransform Transform) {
	t.Helper()
	for _, fm := range fields {
		if indexEqual(fm.Index, wantIndex) {
			if fm.DataType != wantDataType {
				t.Errorf("field %v: dataType = %v, want %v", wantIndex, fm.DataType, wantDataType)
			}
			if fm.Transform != wantTransform {
				t.Errorf("field %v: transform = %v, want %v", wantIndex, fm.Transform, wantTransform)
			}
			return
		}
	}
	t.Errorf("field with index %v not found", wantIndex)
}

func indexEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
