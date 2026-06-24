package datamask

import (
	"reflect"
	"testing"
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
	Name   string
	Email  string `mask:"email"`   // → RedactStrategy
	Token  string `mask:"hash"`    // → HashStrategy
	Alias  string `mask:"tokenize"` // → TokenizeStrategy
	Phone  string `mask:"partial"`  // → PartialStrategy
	SSN    string `mask:"secret"`   // → RedactStrategy
	Bogus  string `mask:"xyzzy"`    // unknown → RedactStrategy
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

func TestParseTagsSingleTag(t *testing.T) {
	meta := parseTags(reflect.TypeFor[simpleStruct]())
	if len(meta.Fields) != 3 {
		t.Fatalf("expected 3 tagged fields (including unexported), got %d", len(meta.Fields))
	}

	// Field 0: Name — no tag
	// Field 1: Email — mask:"email"
	// Field 2: Phone — mask:"phone"
	// Field 3: ssn — mask:"secret" (unexported, but still discovered by type walk)

	findField(t, meta.Fields, []int{1}, RedactStrategy) // Email
	findField(t, meta.Fields, []int{2}, RedactStrategy) // Phone
	findField(t, meta.Fields, []int{3}, RedactStrategy) // ssn
}

func TestParseTagsUntaggedStruct(t *testing.T) {
	meta := parseTags(reflect.TypeFor[untaggedStruct]())
	if len(meta.Fields) != 0 {
		t.Errorf("expected 0 fields for untagged struct, got %d", len(meta.Fields))
	}
}

func TestParseTagsOptOut(t *testing.T) {
	meta := parseTags(reflect.TypeFor[optOutStruct]())
	// mask:"-" should be excluded, mask:"phone" included
	if len(meta.Fields) != 1 {
		t.Fatalf("expected 1 field (mask:\"-\" excluded), got %d", len(meta.Fields))
	}
	findField(t, meta.Fields, []int{2}, RedactStrategy) // Phone
}

func TestParseTagsMixedStrategies(t *testing.T) {
	meta := parseTags(reflect.TypeFor[mixedStrategy]())

	tests := []struct {
		index    []int
		strategy Strategy
	}{
		{[]int{1}, RedactStrategy},   // Email: mask:"email"
		{[]int{2}, HashStrategy},     // Token: mask:"hash"
		{[]int{3}, TokenizeStrategy}, // Alias: mask:"tokenize"
		{[]int{4}, PartialStrategy},  // Phone: mask:"partial"
		{[]int{5}, RedactStrategy},   // SSN: mask:"secret"
		{[]int{6}, RedactStrategy},   // Bogus: mask:"xyzzy" → default
	}

	for _, tt := range tests {
		findField(t, meta.Fields, tt.index, tt.strategy)
	}
}

func TestParseTagsCaseInsensitive(t *testing.T) {
	meta := parseTags(reflect.TypeFor[caseInsensitive]())
	// Both mask:"EMAIL" and mask:"Phone" should be treated as RedactStrategy
	if len(meta.Fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(meta.Fields))
	}
	findField(t, meta.Fields, []int{0}, RedactStrategy) // Email (tag "EMAIL")
	findField(t, meta.Fields, []int{1}, RedactStrategy) // Phone (tag "Phone")
}

func TestParseTagsEmbeddedStruct(t *testing.T) {
	meta := parseTags(reflect.TypeFor[anonymousEmbed]())
	// The anonymous simpleStruct is promoted. Its tagged fields should appear
	// with indices traversing through the embedded struct.
	// Index: Field 1 of anonymousEmbed is simpleStruct, then field 1 of simpleStruct is Email.
	if len(meta.Fields) != 3 {
		t.Fatalf("expected 3 promoted tagged fields, got %d", len(meta.Fields))
	}
	findField(t, meta.Fields, []int{1, 1}, RedactStrategy) // promoted Email
	findField(t, meta.Fields, []int{1, 2}, RedactStrategy) // promoted Phone
	findField(t, meta.Fields, []int{1, 3}, RedactStrategy) // promoted ssn
}

func TestParseTagsNestedStruct(t *testing.T) {
	meta := parseTags(reflect.TypeFor[embeddedParent]())
	// Inner is a non-anonymous struct — its fields are NOT promoted.
	// The tag walk should NOT discover fields of non-anonymous nested structs.
	if len(meta.Fields) != 0 {
		t.Errorf("expected 0 fields (non-anonymous nested struct not walked), got %d", len(meta.Fields))
	}
}

func TestParseTagsPointerField(t *testing.T) {
	meta := parseTags(reflect.TypeFor[pointerField]())
	// Name has mask:"secret" (direct field)
	// Inner is *simpleStruct — pointer fields are not walked for tags

	if len(meta.Fields) < 1 {
		t.Fatalf("expected at least 1 field (Name), got %d", len(meta.Fields))
	}
	findField(t, meta.Fields, []int{0}, RedactStrategy) // Name
}

func TestParseTagsNonStruct(t *testing.T) {
	meta := parseTags(reflect.TypeFor[int]())
	if len(meta.Fields) != 0 {
		t.Errorf("expected 0 fields for non-struct type, got %d", len(meta.Fields))
	}
}

func TestParseTagsPointerToStruct(t *testing.T) {
	meta := parseTags(reflect.TypeOf(&simpleStruct{}))
	if len(meta.Fields) != 3 {
		t.Fatalf("expected 3 fields via pointer deref, got %d", len(meta.Fields))
	}
}

// -- Helpers --

func findField(t *testing.T, fields []FieldMeta, wantIndex []int, wantStrategy Strategy) {
	t.Helper()
	for _, fm := range fields {
		if indexEqual(fm.Index, wantIndex) {
			if fm.Strategy != wantStrategy {
				t.Errorf("field %v: strategy = %v, want %v", wantIndex, fm.Strategy, wantStrategy)
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
