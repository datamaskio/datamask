package datamask

import (
	"errors"
	"reflect"
	"strings"

	"github.com/datamaskio/datamask/internal/reflectx"
)

// MaskTag is the struct tag key used to mark sensitive fields.
const MaskTag = "mask"

// parseTags walks the struct type t and returns metadata for every field
// tagged with mask:"...". Embedded structs are walked recursively;
// pointer fields are followed (dereferenced).
//
// Tag parsing rules (ADR-0023, clean break — no transform-only tags):
//
//  1. "-" → skip field
//  2. "<dataType>" → transform defaults to redact
//  3. "<dataType>,<transform>[,opts...]" → split on ","; whitespace trimmed;
//     key=value suffixes on the transform token are ignored
//  4. Unknown or empty dataType (including v0.1 "hash", "tokenize",
//     "partial") → ErrUnknownDataType
//  5. Unknown or empty transform → ErrUnknownTransform
//
// Fields tagged mask:"-" are excluded.
func parseTags(t reflect.Type) (*reflectx.TypeMeta, error) {
	meta := &reflectx.TypeMeta{}
	var firstErr error
	discoverFields(t, nil, func(index []int, tag string) {
		dt, tr, err := parseTagValue(tag)
		if err != nil && firstErr == nil {
			firstErr = err
			return
		}
		// Copy the index slice since the walk reuses the backing array.
		idx := make([]int, len(index))
		copy(idx, index)
		path, goType, unexported := describeField(t, idx)
		meta.Fields = append(meta.Fields, reflectx.FieldMeta{
			Index:      idx,
			DataType:   dt,
			Transform:  tr,
			Path:       path,
			GoType:     goType,
			Unexported: unexported,
		})
	})
	return meta, firstErr
}

// parseTagValue parses a mask tag value into a DataType and Transform using
// the shared parser, mapping its errors to the public sentinels. Callers
// filter out mask:"-" before calling.
func parseTagValue(tag string) (reflectx.DataType, reflectx.Transform, error) {
	dt, tr, err := reflectx.ParseTag(tag)
	switch {
	case errors.Is(err, reflectx.ErrUnknownDataType):
		return reflectx.DataTypeUnknown, 0, ErrUnknownDataType
	case errors.Is(err, reflectx.ErrUnknownTransform):
		return reflectx.DataTypeUnknown, 0, ErrUnknownTransform
	}
	return dt, tr, err
}

// discoverFields walks the struct type t and calls onField for each field
// that has a mask tag. Embedded (anonymous) struct fields are promoted:
// their fields are discovered with the index path traversing through the
// embedded struct. Pointer fields are dereferenced.
//
// prefix is the index path to the current struct within the root type.
func discoverFields(t reflect.Type, prefix []int, onField func(index []int, tag string)) {
	// Dereference pointer types.
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}

	for i := range t.NumField() {
		f := t.Field(i)
		index := append(prefix, i)

		if f.Anonymous {
			// Embedded struct — promote its fields.
			discoverFields(f.Type, index, onField)
			continue
		}

		tag, ok := f.Tag.Lookup(MaskTag)
		if !ok {
			continue
		}

		// Rule 1: mask:"-" → skip the field.
		if tag == "-" {
			continue
		}

		onField(index, tag)
	}
}

// describeField resolves a field-index path against t, returning the dotted
// Go field path, the leaf field's type, and whether the leaf is unexported.
func describeField(t reflect.Type, index []int) (path, goType string, unexported bool) {
	var names []string
	var leaf reflect.StructField
	for _, i := range index {
		if t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		leaf = t.Field(i)
		names = append(names, leaf.Name)
		t = leaf.Type
	}
	return strings.Join(names, "."), leaf.Type.String(), !leaf.IsExported()
}
