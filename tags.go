package datamask

import (
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
		meta.Fields = append(meta.Fields, reflectx.FieldMeta{
			Index:     idx,
			DataType:  dt,
			Transform: tr,
		})
	})
	return meta, firstErr
}

// parseTagValue parses a mask tag value into a DataType and Transform.
// Callers filter out mask:"-" before calling.
func parseTagValue(tag string) (reflectx.DataType, reflectx.Transform, error) {
	dtStr, rest, hasTransform := strings.Cut(tag, ",")
	dt := dataTypeFromString(strings.TrimSpace(dtStr))
	if dt == reflectx.DataTypeUnknown {
		return reflectx.DataTypeUnknown, 0, ErrUnknownDataType
	}
	if !hasTransform {
		return dt, reflectx.TransformRedact, nil
	}

	// Only the first token after the data type is the transform; the rest
	// are options and are ignored.
	trStr, _, _ := strings.Cut(rest, ",")
	trStr, _, _ = strings.Cut(trStr, "=")
	trStr = strings.TrimSpace(trStr)
	if !isKnownTransform(trStr) {
		return reflectx.DataTypeUnknown, 0, ErrUnknownTransform
	}
	return dt, transformFromString(trStr), nil
}

// dataTypeFromString maps a string to a DataType.
func dataTypeFromString(s string) reflectx.DataType {
	switch strings.ToLower(s) {
	case "email":
		return reflectx.DataTypeEmail
	case "phone":
		return reflectx.DataTypePhone
	case "ssn":
		return reflectx.DataTypeSSN
	case "credit-card", "creditcard":
		return reflectx.DataTypeCreditCard
	case "password":
		return reflectx.DataTypePassword
	case "secret":
		return reflectx.DataTypeSecret
	case "api-key", "apikey":
		return reflectx.DataTypeAPIKey
	case "jwt":
		return reflectx.DataTypeJWT
	default:
		return reflectx.DataTypeUnknown
	}
}

// transformFromString maps a string to a Transform.
func transformFromString(s string) reflectx.Transform {
	switch strings.ToLower(s) {
	case "redact":
		return reflectx.TransformRedact
	case "hash":
		return reflectx.TransformHash
	case "tokenize":
		return reflectx.TransformTokenize
	case "partial":
		return reflectx.TransformPartial
	default:
		return reflectx.TransformRedact
	}
}

// isKnownTransform reports whether s is a recognized transform string.
func isKnownTransform(s string) bool {
	switch strings.ToLower(s) {
	case "redact", "hash", "tokenize", "partial":
		return true
	}
	return false
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
